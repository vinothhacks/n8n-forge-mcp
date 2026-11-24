//! n8n 2.47+ dual-bucket (`Retry-After`, `X-RateLimit-Limit/Remaining/Reset`) rate-limit engine
//! tracking global & per-endpoint read/write buckets + conservative local `governor` fallback.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::DateTime;
use governor::{Quota, RateLimiter};
use http::{HeaderMap, Method, StatusCode};
use n8n_types::{N8nError, N8nResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Read vs Write request bucket classification matching n8n 2.47+ Public API rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MethodClass {
    Read,
    Write,
}

impl MethodClass {
    #[must_use]
    pub fn from_http_method(method: &Method) -> Self {
        match *method {
            Method::GET | Method::HEAD | Method::OPTIONS => Self::Read,
            _ => Self::Write,
        }
    }
}

/// Configuration for server-header pacing and conservative local `governor` fallback quotas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    pub local_read_per_sec: u32,
    pub local_write_per_sec: u32,
    pub max_wait_ms: u64,
    pub max_429_retries: u8,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            local_read_per_sec: 40,
            local_write_per_sec: 10,
            max_wait_ms: 15_000,
            max_429_retries: 2,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct BucketWindow {
    limit: Option<u64>,
    remaining: Option<u64>,
    reset_after: Option<Duration>,
    blocked_until: Option<Instant>,
}

/// Public diagnostic snapshot of observed server rate-limit headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BucketSnapshot {
    pub server_headers_observed: bool,
    pub global_read_remaining: Option<u64>,
    pub global_write_remaining: Option<u64>,
    pub endpoint_buckets_tracked: usize,
    pub total_pacing_sleeps_ms: u64,
}

#[derive(Debug, Default)]
struct RateLimitState {
    server_headers_observed: bool,
    global_read: BucketWindow,
    global_write: BucketWindow,
    endpoint_buckets: HashMap<(MethodClass, String), BucketWindow>,
}

type DirectLimiter = RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

/// Thread-safe n8n 2.47+ rate-limit tracker with server-header priority and `governor` fallback.
pub struct RateLimitEngine {
    instance: String,
    config: RateLimitConfig,
    state: Mutex<RateLimitState>,
    local_read_limiter: DirectLimiter,
    local_write_limiter: DirectLimiter,
    total_pacing_sleeps_ms: AtomicU64,
}

impl RateLimitEngine {
    #[must_use]
    pub fn new(instance: impl Into<String>, config: RateLimitConfig) -> Self {
        let read_rps = NonZeroU32::new(config.local_read_per_sec.max(1)).expect("non-zero u32");
        let write_rps = NonZeroU32::new(config.local_write_per_sec.max(1)).expect("non-zero u32");
        Self {
            instance: instance.into(),
            config,
            state: Mutex::new(RateLimitState::default()),
            local_read_limiter: RateLimiter::direct(Quota::per_second(read_rps)),
            local_write_limiter: RateLimiter::direct(Quota::per_second(write_rps)),
            total_pacing_sleeps_ms: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub const fn config(&self) -> RateLimitConfig {
        self.config
    }

    /// Awaits any active server `Retry-After` / `X-RateLimit-Reset` window on both the global
    /// read/write bucket AND the per-endpoint read/write bucket, or applies the local `governor`
    /// limiter when server rate-limit headers are not active.
    pub async fn acquire_permit(&self, class: MethodClass, path_template: &str) -> N8nResult<()> {
        let (wait_dur, use_local_governor, bucket_name) = {
            let guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = Instant::now();
            let global_bucket = match class {
                MethodClass::Read => &guard.global_read,
                MethodClass::Write => &guard.global_write,
            };
            let ep_bucket = guard
                .endpoint_buckets
                .get(&(class, path_template.to_owned()));

            let global_wait = global_bucket
                .blocked_until
                .and_then(|until| until.checked_duration_since(now));
            let ep_wait = ep_bucket
                .and_then(|b| b.blocked_until)
                .and_then(|until| until.checked_duration_since(now));

            let combined = match (global_wait, ep_wait) {
                (Some(g), Some(e)) if g >= e => (Some(g), format!("global_{class:?}")),
                (Some(_), Some(e)) => (Some(e), format!("endpoint_{class:?}:{path_template}")),
                (Some(g), None) => (Some(g), format!("global_{class:?}")),
                (None, Some(e)) => (Some(e), format!("endpoint_{class:?}:{path_template}")),
                (None, None) => (None, String::new()),
            };
            (combined.0, !guard.server_headers_observed, combined.1)
        };

        if let Some(delay) = wait_dur {
            let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            if delay_ms > self.config.max_wait_ms {
                return Err(N8nError::rate_limited(
                    &self.instance,
                    Some(bucket_name),
                    Some(delay_ms),
                    format!(
                        "rate-limit window ({delay_ms} ms) exceeds max_wait_ms ({} ms)",
                        self.config.max_wait_ms
                    ),
                ));
            }
            tokio::time::sleep(delay).await;
            self.total_pacing_sleeps_ms
                .fetch_add(delay_ms, Ordering::Relaxed);
        } else if use_local_governor {
            match class {
                MethodClass::Read => self.local_read_limiter.until_ready().await,
                MethodClass::Write => self.local_write_limiter.until_ready().await,
            }
        }

        Ok(())
    }

    /// Updates global and per-endpoint read/write buckets from response headers (`Retry-After`,
    /// `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `X-RateLimit-Policy` / `X-RateLimit-Scope`).
    /// Returns parsed wait duration if `429` or `Remaining == 0` was observed.
    pub fn record_response_headers(
        &self,
        class: MethodClass,
        path_template: &str,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Option<Duration> {
        let retry_after = parse_retry_after(headers);
        let limit = parse_u64_header(headers, "x-ratelimit-limit");
        let remaining = parse_u64_header(headers, "x-ratelimit-remaining");
        let reset = parse_reset_duration(headers);
        let scope = headers
            .get("x-ratelimit-scope")
            .or_else(|| headers.get("x-ratelimit-bucket"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase);

        let any_rl_header =
            retry_after.is_some() || limit.is_some() || remaining.is_some() || reset.is_some();
        if !any_rl_header && status != StatusCode::TOO_MANY_REQUESTS {
            return None;
        }

        let effective_wait = if status == StatusCode::TOO_MANY_REQUESTS || remaining == Some(0) {
            retry_after
                .or(reset)
                .or(if status == StatusCode::TOO_MANY_REQUESTS {
                    Some(Duration::from_millis(250))
                } else {
                    None
                })
        } else {
            None
        };

        let now = Instant::now();
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if limit.is_some() || remaining.is_some() || reset.is_some() {
            guard.server_headers_observed = true;
        }

        let is_global_only = scope.as_deref() == Some("global");
        let is_endpoint_only = scope.as_deref() == Some("endpoint");

        if !is_endpoint_only {
            let g_bucket = match class {
                MethodClass::Read => &mut guard.global_read,
                MethodClass::Write => &mut guard.global_write,
            };
            apply_window_update(g_bucket, limit, remaining, reset, effective_wait, now);
        }

        if !is_global_only {
            let ep_bucket = guard
                .endpoint_buckets
                .entry((class, path_template.to_owned()))
                .or_default();
            apply_window_update(ep_bucket, limit, remaining, reset, effective_wait, now);
        }

        effective_wait
    }

    pub fn record_explicit_sleep(&self, slept: Duration) {
        let ms = u64::try_from(slept.as_millis()).unwrap_or(u64::MAX);
        self.total_pacing_sleeps_ms.fetch_add(ms, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> BucketSnapshot {
        let guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        BucketSnapshot {
            server_headers_observed: guard.server_headers_observed,
            global_read_remaining: guard.global_read.remaining,
            global_write_remaining: guard.global_write.remaining,
            endpoint_buckets_tracked: guard.endpoint_buckets.len(),
            total_pacing_sleeps_ms: self.total_pacing_sleeps_ms.load(Ordering::Relaxed),
        }
    }
}

fn apply_window_update(
    bucket: &mut BucketWindow,
    limit: Option<u64>,
    remaining: Option<u64>,
    reset: Option<Duration>,
    effective_wait: Option<Duration>,
    now: Instant,
) {
    if let Some(l) = limit {
        bucket.limit = Some(l);
    }
    if let Some(r) = remaining {
        bucket.remaining = Some(r);
    }
    if let Some(rs) = reset {
        bucket.reset_after = Some(rs);
    }
    if let Some(wait) = effective_wait {
        let candidate = now + wait;
        bucket.blocked_until = Some(match bucket.blocked_until {
            Some(existing) if existing > candidate => existing,
            _ => candidate,
        });
    } else if remaining.is_some_and(|r| r > 0) {
        bucket.blocked_until = None;
    }
}

fn parse_u64_header(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Parses `Retry-After` as either integer/decimal seconds OR HTTP-date (RFC 2822 / IMF-fixdate).
#[must_use]
pub fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get("retry-after")?.to_str().ok()?.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    if let Ok(secs_f) = raw.parse::<f64>()
        && secs_f.is_finite()
        && secs_f >= 0.0
    {
        return Some(Duration::from_secs_f64(secs_f));
    }
    if let Ok(parsed_dt) = DateTime::parse_from_rfc2822(raw) {
        let now_utc = chrono::Utc::now();
        let diff = parsed_dt.with_timezone(&chrono::Utc) - now_utc;
        if diff.num_milliseconds() > 0 {
            return Some(Duration::from_millis(
                diff.num_milliseconds().cast_unsigned(),
            ));
        }
        return Some(Duration::ZERO);
    }
    None
}

/// Parses `X-RateLimit-Reset` supporting delta-seconds, Unix epoch seconds, or Unix epoch milliseconds.
#[must_use]
pub fn parse_reset_duration(headers: &HeaderMap) -> Option<Duration> {
    let raw_val = parse_u64_header(headers, "x-ratelimit-reset")?;
    let now_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    if raw_val > 1_000_000_000_000 {
        // Epoch milliseconds
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis(),
        )
        .unwrap_or(0);
        Some(Duration::from_millis(raw_val.saturating_sub(now_ms)))
    } else if raw_val > 1_500_000_000 {
        // Epoch seconds
        Some(Duration::from_secs(raw_val.saturating_sub(now_epoch_secs)))
    } else {
        // Delta seconds
        Some(Duration::from_secs(raw_val))
    }
}
