//! URL normalization, origin pinning, path-segment sanitization, and DNS/IP SSRF guard.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use n8n_types::{N8nError, N8nResult};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Characters encoded in URL path segments (RFC 3986 path-segment unsafe set).
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'\\');

/// SSRF and transport origin policy for outbound n8n HTTP connections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SsrfPolicy {
    /// Permits `http://` and loopback IP resolution ONLY for `127.0.0.1`, `[::1]`, or `localhost`
    /// during local development or `wiremock` contract testing.
    pub allow_loopback_http: bool,
    /// Permits RFC1918 / IPv6 ULA private IP resolution ONLY when matching the explicitly configured
    /// trusted instance host (never permits link-local `169.254.0.0/16` or cloud metadata).
    pub trust_configured_private_host: bool,
    /// Optional explicit allowlist of trusted private IPs for the configured instance host.
    #[serde(default)]
    pub trusted_private_ips: Vec<IpAddr>,
}

/// Normalized, origin-pinned endpoint descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub base_url: Url,
}

impl OriginEndpoint {
    /// Checks that `candidate` has the exact same `(scheme, host, port)` as this pinned origin.
    pub fn ensure_same_origin(&self, candidate: &Url) -> N8nResult<()> {
        let cand_scheme = candidate.scheme();
        let cand_host = candidate
            .host_str()
            .ok_or_else(|| N8nError::ssrf_blocked(candidate.as_str(), "URL missing host"))?;
        let cand_port = candidate.port_or_known_default().ok_or_else(|| {
            N8nError::ssrf_blocked(candidate.as_str(), "URL missing known default port")
        })?;

        if !cand_scheme.eq_ignore_ascii_case(&self.scheme)
            || !cand_host.eq_ignore_ascii_case(&self.host)
            || cand_port != self.port
        {
            return Err(N8nError::ssrf_blocked(
                format!("{cand_scheme}://{cand_host}:{cand_port}"),
                format!(
                    "cross-origin request or redirect refused (pinned to {}://{}:{})",
                    self.scheme, self.host, self.port
                ),
            ));
        }
        Ok(())
    }
}

/// Validates and percent-encodes a single URL path segment, rejecting empty values, `.` / `..`,
/// slashes, backslashes, encoded path separators (`%2f`, `%5c`), and control bytes.
pub fn validate_path_segment(segment_label: &str, raw: &str) -> N8nResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(N8nError::validation(
            "local",
            vec![format!("empty path segment `{segment_label}`")],
            format!("path parameter `{segment_label}` cannot be empty"),
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
    {
        return Err(N8nError::ssrf_blocked(
            segment_label,
            format!("disallowed path traversal or separator in `{segment_label}`"),
        ));
    }
    Ok(utf8_percent_encode(trimmed, PATH_SEGMENT_ENCODE_SET).to_string())
}

/// Returns `true` if `host_str` is strictly a loopback literal/name (`127.0.0.1`, `[::1]`, `::1`, `localhost`).
#[must_use]
pub fn is_strict_loopback_host(host_str: &str) -> bool {
    let stripped = host_str
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_str);
    stripped.eq_ignore_ascii_case("localhost")
        || stripped == "127.0.0.1"
        || stripped == "::1"
        || stripped
            .parse::<Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
        || stripped
            .parse::<Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn is_forbidden_metadata_hostname(host_str: &str) -> bool {
    let h = host_str.trim_end_matches('.').to_ascii_lowercase();
    matches!(
        h.as_str(),
        "metadata"
            | "metadata.google.internal"
            | "metadata.goog"
            | "instance-data"
            | "instance-data.ec2.internal"
            | "169.254.169.254"
            | "100.100.100.200"
    )
}

/// Validates a resolved or literal `IpAddr` against SSRF rules.
pub fn validate_ip_address(
    ip: IpAddr,
    target_label: &str,
    is_pinned_instance_host: bool,
    policy: &SsrfPolicy,
) -> N8nResult<()> {
    // Unwrap IPv4-mapped IPv6 (`::ffff:a.b.c.d`) so IPv6 notation cannot bypass IPv4 blocks!
    let normalized_ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    };

    match normalized_ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if v4.is_unspecified() || octets[0] == 0 {
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "unspecified IPv4 address (0.0.0.0/8) is forbidden",
                ));
            }
            if v4.is_broadcast() || v4.is_multicast() {
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "broadcast/multicast IPv4 address is forbidden",
                ));
            }
            // Link-local 169.254.0.0/16 & cloud metadata (AWS/GCP/Azure/Alibaba) ALWAYS blocked!
            if v4.is_link_local()
                || (octets[0] == 169 && octets[1] == 254)
                || octets == [100, 100, 100, 200]
            {
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "link-local / cloud metadata IPv4 address is unconditionally blocked",
                ));
            }
            // CGNAT 100.64.0.0/10 (includes cloud internal ranges)
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "shared/CGNAT IPv4 range (100.64.0.0/10) is blocked",
                ));
            }
            if v4.is_loopback() {
                if is_pinned_instance_host && policy.allow_loopback_http {
                    return Ok(());
                }
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "loopback IPv4 (127.0.0.0/8) is blocked unless allow_loopback_http is opted in for loopback host",
                ));
            }
            if v4.is_private() {
                let explicitly_trusted = is_pinned_instance_host
                    && (policy.trust_configured_private_host
                        || policy.trusted_private_ips.contains(&IpAddr::V4(v4)));
                if explicitly_trusted {
                    return Ok(());
                }
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "RFC1918 private IPv4 address is blocked unless explicitly configured as trusted instance host",
                ));
            }
            Ok(())
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            if v6.is_unspecified() || v6.is_multicast() {
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "unspecified/multicast IPv6 address is forbidden",
                ));
            }
            // IPv6 link-local fe80::/10 or AWS EC2 IPv6 IMDS fd00:ec2::254 ALWAYS blocked!
            if v6.is_unicast_link_local()
                || (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] == 0xfd00
                    && segs[1] == 0x0ec2
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0
                    && segs[5] == 0
                    && segs[6] == 0
                    && segs[7] == 0x0254)
            {
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "link-local / cloud metadata IPv6 address is unconditionally blocked",
                ));
            }
            if v6.is_loopback() {
                if is_pinned_instance_host && policy.allow_loopback_http {
                    return Ok(());
                }
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "loopback IPv6 (::1) is blocked unless allow_loopback_http is opted in for loopback host",
                ));
            }
            // Unique Local Address fc00::/7
            if (segs[0] & 0xfe00) == 0xfc00 {
                let explicitly_trusted = is_pinned_instance_host
                    && (policy.trust_configured_private_host
                        || policy.trusted_private_ips.contains(&IpAddr::V6(v6)));
                if explicitly_trusted {
                    return Ok(());
                }
                return Err(N8nError::ssrf_blocked(
                    target_label,
                    "IPv6 ULA private address (fc00::/7) is blocked unless explicitly configured as trusted instance host",
                ));
            }
            Ok(())
        }
    }
}

/// Normalizes an n8n base URL, enforces HTTPS (except explicit loopback dev/test opt-in),
/// blocks userinfo/fragments/queries/metadata hosts, and validates IP literals immediately.
pub fn normalize_and_validate_url(raw_url: &str, policy: &SsrfPolicy) -> N8nResult<OriginEndpoint> {
    let parsed = Url::parse(raw_url.trim())
        .map_err(|e| N8nError::config(format!("invalid n8n URL: {e}")))?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(N8nError::ssrf_blocked(
            "url_with_credentials",
            "embedded userinfo credentials in n8n URL are forbidden",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(N8nError::config(
            "n8n base URL must not include query parameters or fragments",
        ));
    }

    let scheme = parsed.scheme().to_ascii_lowercase();
    let host_str = parsed
        .host_str()
        .ok_or_else(|| N8nError::config("n8n base URL must contain a valid host"))?
        .to_owned();

    if is_forbidden_metadata_hostname(&host_str) {
        return Err(N8nError::ssrf_blocked(
            &host_str,
            "cloud metadata hostname is unconditionally blocked",
        ));
    }

    match scheme.as_str() {
        "https" => {}
        "http" => {
            if !(policy.allow_loopback_http && is_strict_loopback_host(&host_str)) {
                return Err(N8nError::ssrf_blocked(
                    format!("http://{host_str}"),
                    "cleartext HTTP is forbidden; HTTPS is required except explicit loopback dev/test mode",
                ));
            }
        }
        other => {
            return Err(N8nError::ssrf_blocked(
                other,
                format!("unsupported URL scheme `{other}` (only https allowed)"),
            ));
        }
    }

    if host_str.eq_ignore_ascii_case("localhost") && !policy.allow_loopback_http {
        return Err(N8nError::ssrf_blocked(
            &host_str,
            "localhost is blocked unless allow_loopback_http is explicitly enabled",
        ));
    }

    match parsed.host() {
        Some(Host::Ipv4(v4)) => {
            validate_ip_address(IpAddr::V4(v4), &host_str, true, policy)?;
        }
        Some(Host::Ipv6(v6)) => {
            validate_ip_address(IpAddr::V6(v6), &host_str, true, policy)?;
        }
        Some(Host::Domain(_)) => {}
        None => {
            return Err(N8nError::config("n8n base URL missing host"));
        }
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| N8nError::config("n8n base URL missing default port"))?;

    let mut clean = parsed;
    let trimmed_path = clean.path().trim_end_matches('/').to_owned();
    clean.set_path(if trimmed_path.is_empty() {
        "/"
    } else {
        &trimmed_path
    });

    Ok(OriginEndpoint {
        scheme,
        host: host_str,
        port,
        base_url: clean,
    })
}

/// Resolves DNS for `origin` via `tokio::net::lookup_host` and validates EVERY returned `SocketAddr`
/// against `policy` so DNS rebinding to `127.0.0.1`, `169.254.169.254`, or RFC1918 is caught fail-closed.
pub async fn resolve_and_validate_origin(
    origin: &OriginEndpoint,
    policy: &SsrfPolicy,
) -> N8nResult<Vec<SocketAddr>> {
    if let Ok(ip) = origin
        .host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&origin.host)
        .parse::<IpAddr>()
    {
        validate_ip_address(ip, &origin.host, true, policy)?;
        return Ok(vec![SocketAddr::new(ip, origin.port)]);
    }

    let lookup_target = format!("{}:{}", origin.host, origin.port);
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_target)
        .await
        .map_err(|e| {
            N8nError::transport(&origin.host, None, format!("DNS resolution failed: {e}"))
        })?
        .collect();

    if resolved.is_empty() {
        return Err(N8nError::transport(
            &origin.host,
            None,
            "DNS resolution returned zero addresses",
        ));
    }

    // Domain names resolving to loopback are only allowed if host itself is `localhost` + `allow_loopback_http`!
    let domain_may_be_loopback =
        origin.host.eq_ignore_ascii_case("localhost") && policy.allow_loopback_http;

    for sock in &resolved {
        let ip = sock.ip();
        if (ip.is_loopback()
            || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())))
            && !domain_may_be_loopback
        {
            return Err(N8nError::ssrf_blocked(
                &origin.host,
                "DNS hostname resolved to loopback IP (DNS rebinding SSRF blocked)",
            ));
        }
        validate_ip_address(ip, &origin.host, true, policy)?;
    }

    Ok(resolved)
}
