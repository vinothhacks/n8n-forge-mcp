//! Hardened `N8nApiClient` covering all n8n 2.48.7 Public API `/api/v1` resource groups.

use std::sync::Arc;
use std::time::Duration;

use http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode};
use n8n_types::{N8nError, N8nResult, SecretValue, redact_json_value, redact_str};
use reqwest::redirect;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use url::Url;

use crate::idempotency::{IdempotencyStore, Outcome};
use crate::models::{
    CredentialMetadata, DataTableResource, DiscoverPayload, ExecutionResource, FolderResource,
    ListQueryParams, PaginatedList, ProjectResource, TagResource, UserResource, VariableResource,
    WorkflowResource,
};
use crate::rate_limit::{BucketSnapshot, MethodClass, RateLimitConfig, RateLimitEngine};
use crate::ssrf::{
    OriginEndpoint, SsrfPolicy, normalize_and_validate_url, resolve_and_validate_origin,
    validate_path_segment,
};
use crate::streaming::{StreamBudget, read_bounded_response};

const HEADER_N8N_API_KEY: HeaderName = HeaderName::from_static("x-n8n-api-key");
const HEADER_IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const HEADER_CF_CLIENT_ID: HeaderName = HeaderName::from_static("cf-access-client-id");
const HEADER_CF_CLIENT_SECRET: HeaderName = HeaderName::from_static("cf-access-client-secret");

/// Configuration for `N8nApiClient`.
#[derive(Debug, Clone)]
pub struct ApiClientConfig {
    pub instance_alias: String,
    pub base_url: String,
    pub api_key: SecretValue,
    pub cf_access_client_id: Option<String>,
    pub cf_access_client_secret: Option<SecretValue>,
    pub ssrf_policy: SsrfPolicy,
    pub stream_budget: StreamBudget,
    pub rate_limit: RateLimitConfig,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl ApiClientConfig {
    #[must_use]
    pub fn new(
        instance_alias: impl Into<String>,
        base_url: impl Into<String>,
        api_key: SecretValue,
    ) -> Self {
        Self {
            instance_alias: instance_alias.into(),
            base_url: base_url.into(),
            api_key,
            cf_access_client_id: None,
            cf_access_client_secret: None,
            ssrf_policy: SsrfPolicy::default(),
            stream_budget: StreamBudget::default(),
            rate_limit: RateLimitConfig::default(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Origin-pinned, SSRF-hardened, rate-limited, idempotency-aware n8n Public API (`/api/v1`) client.
#[derive(Clone)]
pub struct N8nApiClient {
    inner: Arc<N8nApiClientInner>,
}

struct N8nApiClientInner {
    instance_alias: String,
    origin: OriginEndpoint,
    api_v1_prefix: String,
    api_key: SecretValue,
    cf_access_client_id: Option<String>,
    cf_access_client_secret: Option<SecretValue>,
    ssrf_policy: SsrfPolicy,
    stream_budget: StreamBudget,
    http: reqwest::Client,
    rate_limiter: RateLimitEngine,
    idempotency: IdempotencyStore,
}

/// Structured low-level HTTP request specification for [`N8nApiClient::send_raw`].
#[derive(Debug, Clone)]
pub struct RawRequest<'a> {
    pub method: Method,
    pub path_template: &'a str,
    pub sub_path: &'a str,
    pub query: &'a [(&'a str, String)],
    pub body: Option<&'a Value>,
    pub operation_id: Option<&'a str>,
    pub accept_mime: &'a str,
}

impl N8nApiClient {
    /// Builds a hardened `N8nApiClient` with `redirect::Policy::none()`, `no_proxy()`, and rustls.
    pub fn new(config: ApiClientConfig) -> N8nResult<Self> {
        if config.api_key.is_empty() {
            return Err(N8nError::unauthenticated(
                &config.instance_alias,
                "N8N_API_KEY is empty or missing",
            ));
        }

        let origin = normalize_and_validate_url(&config.base_url, &config.ssrf_policy)?;
        let base_path = origin.base_url.path().trim_end_matches('/');
        let api_v1_prefix = if base_path.ends_with("/api/v1") {
            base_path.to_owned()
        } else if base_path.is_empty() || base_path == "/" {
            "/api/v1".to_owned()
        } else {
            format!("{base_path}/api/v1")
        };

        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(redirect::Policy::none())
            .no_proxy()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .user_agent(concat!("n8n-rs-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                N8nError::config(format!("failed constructing rustls HTTP client: {e}"))
            })?;

        Ok(Self {
            inner: Arc::new(N8nApiClientInner {
                instance_alias: config.instance_alias.clone(),
                origin,
                api_v1_prefix,
                api_key: config.api_key,
                cf_access_client_id: config.cf_access_client_id,
                cf_access_client_secret: config.cf_access_client_secret,
                ssrf_policy: config.ssrf_policy,
                stream_budget: config.stream_budget,
                http,
                rate_limiter: RateLimitEngine::new(&config.instance_alias, config.rate_limit),
                idempotency: IdempotencyStore::new(&config.instance_alias),
            }),
        })
    }

    #[must_use]
    pub fn instance_alias(&self) -> &str {
        &self.inner.instance_alias
    }

    #[must_use]
    pub fn origin(&self) -> &OriginEndpoint {
        &self.inner.origin
    }

    #[must_use]
    pub fn ssrf_policy(&self) -> &SsrfPolicy {
        &self.inner.ssrf_policy
    }

    #[must_use]
    pub fn http_client(&self) -> &reqwest::Client {
        &self.inner.http
    }

    #[must_use]
    pub fn idempotency_store(&self) -> &IdempotencyStore {
        &self.inner.idempotency
    }

    #[must_use]
    pub fn rate_limit_snapshot(&self) -> BucketSnapshot {
        self.inner.rate_limiter.snapshot()
    }

    /// Checks whether a secret matches this client's `X-N8N-API-KEY` (used to enforce token isolation).
    #[must_use]
    pub fn matches_api_key(&self, candidate: &SecretValue) -> bool {
        self.inner.api_key.matches_secret(candidate)
    }

    /// Non-reversible domain-separated principal identifier derived from the API key + instance alias.
    #[must_use]
    pub fn principal_fingerprint(&self) -> String {
        let full = self
            .inner
            .api_key
            .domain_hash_hex("n8n-rs-mcp/v2/principal-fingerprint");
        format!("p_{}", &full[..24])
    }

    /// Builds a target URL under `/api/v1` and verifies strict same-origin invariants.
    fn build_api_url(&self, sub_path: &str, query: &[(&str, String)]) -> N8nResult<Url> {
        let clean_sub = sub_path.trim_start_matches('/');
        let full_path = if clean_sub.is_empty() {
            self.inner.api_v1_prefix.clone()
        } else {
            format!("{}/{clean_sub}", self.inner.api_v1_prefix)
        };
        let mut target = self.inner.origin.base_url.clone();
        target.set_path(&full_path);
        if !query.is_empty() {
            let mut pairs = target.query_pairs_mut();
            for (k, v) in query {
                pairs.append_pair(k, v);
            }
        }
        self.inner.origin.ensure_same_origin(&target)?;
        Ok(target)
    }

    /// Constructs origin-pinned headers ONLY after `ensure_same_origin` has succeeded.
    fn build_origin_pinned_headers(
        &self,
        target: &Url,
        accept_mime: &str,
        idempotency_key: Option<&str>,
    ) -> N8nResult<HeaderMap> {
        self.inner.origin.ensure_same_origin(target)?;

        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_str(accept_mime)
                .map_err(|_| N8nError::config("invalid Accept header"))?,
        );
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, zstd, deflate, identity"),
        );

        let api_key_val = HeaderValue::from_str(self.inner.api_key.expose_secret())
            .map_err(|_| N8nError::config("N8N_API_KEY contains invalid HTTP header bytes"))?;
        headers.insert(HEADER_N8N_API_KEY, api_key_val);

        if let Some(ref cf_id) = self.inner.cf_access_client_id {
            let v = HeaderValue::from_str(cf_id)
                .map_err(|_| N8nError::config("invalid CF-Access-Client-Id header"))?;
            headers.insert(HEADER_CF_CLIENT_ID, v);
        }
        if let Some(ref cf_secret) = self.inner.cf_access_client_secret
            && !cf_secret.is_empty()
        {
            let v = HeaderValue::from_str(cf_secret.expose_secret())
                .map_err(|_| N8nError::config("invalid CF-Access-Client-Secret header"))?;
            headers.insert(HEADER_CF_CLIENT_SECRET, v);
        }

        if let Some(idem) = idempotency_key {
            let v = HeaderValue::from_str(idem)
                .map_err(|_| N8nError::config("invalid Idempotency-Key header"))?;
            headers.insert(HEADER_IDEMPOTENCY_KEY, v);
        }

        Ok(headers)
    }

    /// Executes an HTTP request with pre-flight DNS SSRF validation, dual-bucket rate-limit pacing,
    /// `Idempotency-Key` management, redirect blocking, and bounded streaming decompression.
    pub async fn send_raw(&self, spec: RawRequest<'_>) -> N8nResult<(StatusCode, Vec<u8>)> {
        let RawRequest {
            method,
            path_template,
            sub_path,
            query,
            body,
            operation_id,
            accept_mime,
        } = spec;
        let target_url = self.build_api_url(sub_path, query)?;
        let _validated_addrs =
            resolve_and_validate_origin(&self.inner.origin, &self.inner.ssrf_policy).await?;

        let class = MethodClass::from_http_method(&method);
        let is_mutating = class == MethodClass::Write;

        let idempotency_key = if let Some(op_id) = operation_id {
            self.inner
                .idempotency
                .resolve_key(&method, path_template, op_id, body)?
        } else {
            None
        };

        let can_auto_retry_429 = !is_mutating || idempotency_key.is_some();
        let max_retries = if can_auto_retry_429 {
            self.inner.rate_limiter.config().max_429_retries
        } else {
            0
        };

        let mut attempt: u8 = 0;
        loop {
            self.inner
                .rate_limiter
                .acquire_permit(class, path_template)
                .await?;

            let mut headers = self.build_origin_pinned_headers(
                &target_url,
                accept_mime,
                idempotency_key.as_deref(),
            )?;

            let mut req = self
                .inner
                .http
                .request(method.clone(), target_url.clone())
                .headers(headers.clone());

            if let Some(json_body) = body {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                let serialized = serde_json::to_vec(json_body).map_err(|e| {
                    N8nError::protocol(format!("failed serializing request JSON: {e}"))
                })?;
                req = req
                    .header(CONTENT_TYPE, "application/json")
                    .body(serialized);
            }

            let response = match req.send().await {
                Ok(resp) => resp,
                Err(err) => {
                    if err.is_timeout() {
                        if let Some(op_id) = operation_id
                            && is_mutating
                        {
                            self.inner.idempotency.mark_uncertain_timeout(op_id);
                        }
                        return Err(N8nError::timeout_unknown(
                            &self.inner.instance_alias,
                            method.as_str(),
                            path_template,
                            is_mutating,
                            format!("HTTP request timed out: {}", redact_str(&err.to_string())),
                        ));
                    }
                    return Err(N8nError::transport(
                        &self.inner.instance_alias,
                        err.status().map(|s| s.as_u16()),
                        format!("HTTP transport failure: {}", redact_str(&err.to_string())),
                    ));
                }
            };

            let status = response.status();
            let observed_wait = self.inner.rate_limiter.record_response_headers(
                class,
                path_template,
                status,
                response.headers(),
            );

            // Never follow 3xx redirects; surface SSRF/redirect refusal without forwarding credentials!
            if status.is_redirection() {
                let loc = response
                    .headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<missing Location>");
                return Err(N8nError::ssrf_blocked(
                    loc,
                    format!(
                        "HTTP {} redirect blocked (credentials are never forwarded across redirects)",
                        status.as_u16()
                    ),
                ));
            }

            if status == StatusCode::TOO_MANY_REQUESTS {
                let wait_dur = observed_wait.unwrap_or(Duration::from_millis(250));
                let wait_ms = u64::try_from(wait_dur.as_millis()).unwrap_or(u64::MAX);
                if attempt < max_retries && wait_ms <= self.inner.rate_limiter.config().max_wait_ms
                {
                    attempt += 1;
                    tokio::time::sleep(wait_dur).await;
                    self.inner.rate_limiter.record_explicit_sleep(wait_dur);
                    continue;
                }
                let body_bytes = read_bounded_response(
                    &self.inner.instance_alias,
                    response,
                    self.inner.stream_budget,
                )
                .await
                .unwrap_or_default();
                let msg = extract_safe_error_message(&body_bytes, "rate limit exceeded");
                return Err(N8nError::rate_limited(
                    &self.inner.instance_alias,
                    Some(format!("{class:?}:{path_template}")),
                    Some(wait_ms),
                    msg,
                ));
            }

            let body_bytes = read_bounded_response(
                &self.inner.instance_alias,
                response,
                self.inner.stream_budget,
            )
            .await?;

            if status.is_success() {
                return Ok((status, body_bytes));
            }

            return Err(self.map_error_status(status, path_template, &body_bytes));
        }
    }

    fn map_error_status(
        &self,
        status: StatusCode,
        path_template: &str,
        body_bytes: &[u8],
    ) -> N8nError {
        let msg = extract_safe_error_message(
            body_bytes,
            status.canonical_reason().unwrap_or("HTTP error"),
        );
        match status {
            StatusCode::UNAUTHORIZED => N8nError::unauthenticated(&self.inner.instance_alias, msg),
            StatusCode::FORBIDDEN => N8nError::forbidden(
                &self.inner.instance_alias,
                Some(path_template.to_owned()),
                msg,
            ),
            StatusCode::NOT_FOUND => {
                N8nError::not_found_or_concealed(&self.inner.instance_alias, path_template, msg)
            }
            StatusCode::CONFLICT => N8nError::conflict(
                &self.inner.instance_alias,
                Some(path_template.to_owned()),
                msg,
            ),
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => N8nError::validation(
                &self.inner.instance_alias,
                vec![path_template.to_owned()],
                msg,
            ),
            StatusCode::PAYLOAD_TOO_LARGE => N8nError::payload_too_large(
                self.inner.stream_budget.max_compressed_bytes,
                0,
                "remote_413",
            ),
            other => N8nError::transport(&self.inner.instance_alias, Some(other.as_u16()), msg),
        }
    }

    async fn request_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path_template: &str,
        sub_path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        operation_id: Option<&str>,
    ) -> N8nResult<T> {
        let (_status, bytes) = self
            .send_raw(RawRequest {
                method,
                path_template,
                sub_path,
                query,
                body,
                operation_id,
                accept_mime: "application/json",
            })
            .await?;
        let slice = if bytes.is_empty() {
            b"null".as_slice()
        } else {
            bytes.as_slice()
        };
        serde_json::from_slice::<T>(slice).map_err(|e| {
            N8nError::protocol(format!("invalid JSON response for {path_template}: {e}"))
        })
    }

    /// Executes an idempotent `POST` returning `Outcome::UnknownNeedsReconcile` on transport timeout
    /// instead of losing the idempotency correlation.
    pub async fn post_reconcilable<T: DeserializeOwned>(
        &self,
        path_template: &str,
        sub_path: &str,
        operation_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<T>> {
        let idem_key = self.inner.idempotency.resolve_key(
            &Method::POST,
            path_template,
            operation_id,
            Some(body),
        )?;
        match self
            .request_json::<T>(
                Method::POST,
                path_template,
                sub_path,
                &[],
                Some(body),
                Some(operation_id),
            )
            .await
        {
            Ok(value) => Ok(Outcome::Confirmed { value }),
            Err(N8nError::TimeoutUnknownOutcome { message, .. }) => {
                Ok(Outcome::UnknownNeedsReconcile {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: idem_key,
                    path_template: path_template.to_owned(),
                    reason: message,
                })
            }
            Err(other) => Err(other),
        }
    }

    // -------------------------------------------------------------------------
    // 1. Discovery & OpenAPI
    // -------------------------------------------------------------------------

    pub async fn discover_with_schemas(&self) -> N8nResult<DiscoverPayload> {
        let payload: DiscoverPayload = self
            .request_json(
                Method::GET,
                "/api/v1/discover",
                "discover",
                &[("include", "schemas".to_owned())],
                None,
                None,
            )
            .await?;
        self.register_discovered_idempotent_endpoints(&payload.resources);
        Ok(payload)
    }

    fn register_discovered_idempotent_endpoints(&self, resources: &Value) {
        if let Some(obj) = resources.as_object() {
            for group in obj.values() {
                if let Some(ops) = group.get("operations").and_then(Value::as_array) {
                    for op in ops {
                        let is_post = op
                            .get("method")
                            .and_then(Value::as_str)
                            .is_some_and(|m| m.eq_ignore_ascii_case("POST"));
                        let idempotent = op
                            .get("idempotent")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        if is_post
                            && idempotent
                            && let Some(path) = op.get("path").and_then(Value::as_str)
                        {
                            let normalized = if path.starts_with("/api/v1") {
                                path.to_owned()
                            } else {
                                format!("/api/v1/{}", path.trim_start_matches('/'))
                            };
                            self.inner
                                .idempotency
                                .register_supported_post_template(normalized);
                        }
                    }
                }
            }
        }
    }

    pub async fn get_openapi_yaml(&self) -> N8nResult<Value> {
        let (_status, bytes) = self
            .send_raw(RawRequest {
                method: Method::GET,
                path_template: "/api/v1/openapi.yml",
                sub_path: "openapi.yml",
                query: &[],
                body: None,
                operation_id: None,
                accept_mime: "application/yaml, text/yaml, application/json",
            })
            .await?;
        let text = String::from_utf8(bytes)
            .map_err(|_| N8nError::protocol("non-UTF8 OpenAPI specification"))?;
        yaml_serde::from_str::<Value>(&text)
            .map_err(|e| N8nError::protocol(format!("failed parsing openapi.yml: {e}")))
    }

    // -------------------------------------------------------------------------
    // 2. Workflows (/api/v1/workflows)
    // -------------------------------------------------------------------------

    pub async fn list_workflows(
        &self,
        params: &ListQueryParams,
    ) -> N8nResult<PaginatedList<WorkflowResource>> {
        let query = build_list_query(params);
        self.request_json(
            Method::GET,
            "/api/v1/workflows",
            "workflows",
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn get_workflow(
        &self,
        workflow_id: &str,
        exclude_pinned_data: bool,
    ) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let mut query = Vec::new();
        if exclude_pinned_data {
            query.push(("excludePinnedData", "true".to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/workflows/{id}",
            &format!("workflows/{id}"),
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn create_workflow(
        &self,
        operation_id: &str,
        workflow_body: &Value,
    ) -> N8nResult<Outcome<WorkflowResource>> {
        self.post_reconcilable(
            "/api/v1/workflows",
            "workflows",
            operation_id,
            workflow_body,
        )
        .await
    }

    pub async fn update_workflow(
        &self,
        workflow_id: &str,
        workflow_body: &Value,
    ) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::PUT,
            "/api/v1/workflows/{id}",
            &format!("workflows/{id}"),
            &[],
            Some(workflow_body),
            None,
        )
        .await
    }

    pub async fn delete_workflow(&self, workflow_id: &str) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/workflows/{id}",
            &format!("workflows/{id}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn archive_workflow(&self, workflow_id: &str) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/workflows/{id}/archive",
            &format!("workflows/{id}/archive"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn unarchive_workflow(&self, workflow_id: &str) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/workflows/{id}/unarchive",
            &format!("workflows/{id}/unarchive"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn transfer_workflow(
        &self,
        workflow_id: &str,
        destination_project_id: &str,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let body = json!({ "destinationProjectId": destination_project_id });
        self.request_json(
            Method::PUT,
            "/api/v1/workflows/{id}/transfer",
            &format!("workflows/{id}/transfer"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn publish_workflow(
        &self,
        workflow_id: &str,
        publish_body: Option<&Value>,
    ) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/workflows/{id}/publish",
            &format!("workflows/{id}/publish"),
            &[],
            publish_body,
            None,
        )
        .await
    }

    pub async fn unpublish_workflow(&self, workflow_id: &str) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/workflows/{id}/unpublish",
            &format!("workflows/{id}/unpublish"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn activate_workflow(&self, workflow_id: &str) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/workflows/{id}/activate",
            &format!("workflows/{id}/activate"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn deactivate_workflow(&self, workflow_id: &str) -> N8nResult<WorkflowResource> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/workflows/{id}/deactivate",
            &format!("workflows/{id}/deactivate"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn get_workflow_history(
        &self,
        workflow_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/workflows/{id}/history",
            &format!("workflows/{id}/history"),
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn get_workflow_version(
        &self,
        workflow_id: &str,
        workflow_version_id: &str,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let ver = validate_path_segment("workflow_version_id", workflow_version_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/workflows/{id}/versions/{versionId}",
            &format!("workflows/{id}/versions/{ver}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn get_workflow_tags(&self, workflow_id: &str) -> N8nResult<Vec<TagResource>> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/workflows/{id}/tags",
            &format!("workflows/{id}/tags"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn update_workflow_tags(
        &self,
        workflow_id: &str,
        tag_ids: &[String],
    ) -> N8nResult<Vec<TagResource>> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let body: Value = tag_ids
            .iter()
            .map(|tid| json!({ "id": tid }))
            .collect::<Vec<_>>()
            .into();
        self.request_json(
            Method::PUT,
            "/api/v1/workflows/{id}/tags",
            &format!("workflows/{id}/tags"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn get_workflow_dependencies(&self, workflow_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/workflows/{id}/dependencies",
            &format!("workflows/{id}/dependencies"),
            &[],
            None,
            None,
        )
        .await
    }

    // -------------------------------------------------------------------------
    // 3. Executions (/api/v1/executions) & Evaluations (/test-runs)
    // -------------------------------------------------------------------------

    pub async fn list_executions(
        &self,
        workflow_id: Option<&str>,
        status: Option<&str>,
        include_data: bool,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<ExecutionResource>> {
        let mut query = vec![("includeData", include_data.to_string())];
        if let Some(wf) = workflow_id {
            query.push(("workflowId", wf.to_owned()));
        }
        if let Some(st) = status {
            query.push(("status", st.to_owned()));
        }
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/executions",
            "executions",
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn get_execution(
        &self,
        execution_id: &str,
        include_data: bool,
    ) -> N8nResult<ExecutionResource> {
        let id = validate_path_segment("execution_id", execution_id)?;
        let query = [("includeData", include_data.to_string())];
        self.request_json(
            Method::GET,
            "/api/v1/executions/{id}",
            &format!("executions/{id}"),
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn delete_execution(&self, execution_id: &str) -> N8nResult<ExecutionResource> {
        let id = validate_path_segment("execution_id", execution_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/executions/{id}",
            &format!("executions/{id}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn get_execution_tags(&self, execution_id: &str) -> N8nResult<Vec<TagResource>> {
        let id = validate_path_segment("execution_id", execution_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/executions/{id}/tags",
            &format!("executions/{id}/tags"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn update_execution_tags(
        &self,
        execution_id: &str,
        tag_ids: &[String],
    ) -> N8nResult<Vec<TagResource>> {
        let id = validate_path_segment("execution_id", execution_id)?;
        let body: Value = tag_ids
            .iter()
            .map(|tid| json!({ "id": tid }))
            .collect::<Vec<_>>()
            .into();
        self.request_json(
            Method::PUT,
            "/api/v1/executions/{id}/tags",
            &format!("executions/{id}/tags"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn stop_execution(&self, execution_id: &str) -> N8nResult<ExecutionResource> {
        let id = validate_path_segment("execution_id", execution_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/executions/{id}/stop",
            &format!("executions/{id}/stop"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn retry_execution(
        &self,
        execution_id: &str,
        load_workflow: bool,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("execution_id", execution_id)?;
        let body = json!({ "loadWorkflow": load_workflow });
        self.request_json(
            Method::POST,
            "/api/v1/executions/{id}/retry",
            &format!("executions/{id}/retry"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn list_test_runs(&self, workflow_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/workflows/{id}/test-runs",
            &format!("workflows/{id}/test-runs"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn get_test_run(&self, workflow_id: &str, run_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let rid = validate_path_segment("run_id", run_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/workflows/{id}/test-runs/{runId}",
            &format!("workflows/{id}/test-runs/{rid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn start_test_run(
        &self,
        operation_id: &str,
        workflow_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<Value>> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        self.post_reconcilable(
            "/api/v1/workflows/{id}/test-runs",
            &format!("workflows/{id}/test-runs"),
            operation_id,
            body,
        )
        .await
    }

    pub async fn cancel_test_run(&self, workflow_id: &str, run_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let rid = validate_path_segment("run_id", run_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/workflows/{id}/test-runs/{runId}/cancel",
            &format!("workflows/{id}/test-runs/{rid}/cancel"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn delete_test_run(&self, workflow_id: &str, run_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("workflow_id", workflow_id)?;
        let rid = validate_path_segment("run_id", run_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/workflows/{id}/test-runs/{runId}",
            &format!("workflows/{id}/test-runs/{rid}"),
            &[],
            None,
            None,
        )
        .await
    }

    // -------------------------------------------------------------------------
    // 4. Credentials (/api/v1/credentials) — metadata & schema only, never secret echo
    // -------------------------------------------------------------------------

    pub async fn list_credentials(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<CredentialMetadata>> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/credentials",
            "credentials",
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn create_credential(
        &self,
        operation_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<CredentialMetadata>> {
        self.post_reconcilable("/api/v1/credentials", "credentials", operation_id, body)
            .await
    }

    pub async fn update_credential(
        &self,
        credential_id: &str,
        body: &Value,
    ) -> N8nResult<CredentialMetadata> {
        let id = validate_path_segment("credential_id", credential_id)?;
        self.request_json(
            Method::PATCH,
            "/api/v1/credentials/{id}",
            &format!("credentials/{id}"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_credential(&self, credential_id: &str) -> N8nResult<CredentialMetadata> {
        let id = validate_path_segment("credential_id", credential_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/credentials/{id}",
            &format!("credentials/{id}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn transfer_credential(
        &self,
        credential_id: &str,
        destination_project_id: &str,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("credential_id", credential_id)?;
        let body = json!({ "destinationProjectId": destination_project_id });
        self.request_json(
            Method::PUT,
            "/api/v1/credentials/{id}/transfer",
            &format!("credentials/{id}/transfer"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn get_credential_schema(&self, credential_type_name: &str) -> N8nResult<Value> {
        let name = validate_path_segment("credential_type_name", credential_type_name)?;
        self.request_json(
            Method::GET,
            "/api/v1/credentials/schema/{credentialTypeName}",
            &format!("credentials/schema/{name}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn test_credential(&self, credential_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("credential_id", credential_id)?;
        let raw: Value = self
            .request_json(
                Method::POST,
                "/api/v1/credentials/{id}/test",
                &format!("credentials/{id}/test"),
                &[],
                None,
                None,
            )
            .await?;
        Ok(redact_json_value(&raw))
    }

    pub async fn get_credential_dependencies(&self, credential_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("credential_id", credential_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/credentials/{id}/dependencies",
            &format!("credentials/{id}/dependencies"),
            &[],
            None,
            None,
        )
        .await
    }

    // -------------------------------------------------------------------------
    // 5. Data Tables (/api/v1/data-tables)
    // -------------------------------------------------------------------------

    pub async fn list_data_tables(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<DataTableResource>> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/data-tables",
            "data-tables",
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn get_data_table(&self, table_id: &str) -> N8nResult<DataTableResource> {
        let id = validate_path_segment("table_id", table_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/data-tables/{id}",
            &format!("data-tables/{id}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn create_data_table(
        &self,
        operation_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<DataTableResource>> {
        self.post_reconcilable("/api/v1/data-tables", "data-tables", operation_id, body)
            .await
    }

    pub async fn update_data_table(
        &self,
        table_id: &str,
        body: &Value,
    ) -> N8nResult<DataTableResource> {
        let id = validate_path_segment("table_id", table_id)?;
        self.request_json(
            Method::PATCH,
            "/api/v1/data-tables/{id}",
            &format!("data-tables/{id}"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_data_table(&self, table_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/data-tables/{id}",
            &format!("data-tables/{id}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn list_data_table_columns(&self, table_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/data-tables/{id}/columns",
            &format!("data-tables/{id}/columns"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn create_data_table_column(
        &self,
        operation_id: &str,
        table_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<Value>> {
        let id = validate_path_segment("table_id", table_id)?;
        self.post_reconcilable(
            "/api/v1/data-tables/{id}/columns",
            &format!("data-tables/{id}/columns"),
            operation_id,
            body,
        )
        .await
    }

    pub async fn update_data_table_column(
        &self,
        table_id: &str,
        column_id: &str,
        body: &Value,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        let cid = validate_path_segment("column_id", column_id)?;
        self.request_json(
            Method::PATCH,
            "/api/v1/data-tables/{id}/columns/{columnId}",
            &format!("data-tables/{id}/columns/{cid}"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_data_table_column(
        &self,
        table_id: &str,
        column_id: &str,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        let cid = validate_path_segment("column_id", column_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/data-tables/{id}/columns/{columnId}",
            &format!("data-tables/{id}/columns/{cid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn list_data_table_rows(
        &self,
        table_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        let raw: Value = self
            .request_json(
                Method::GET,
                "/api/v1/data-tables/{id}/rows",
                &format!("data-tables/{id}/rows"),
                &query,
                None,
                None,
            )
            .await?;
        Ok(redact_json_value(&raw))
    }

    pub async fn insert_data_table_rows(
        &self,
        operation_id: &str,
        table_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<Value>> {
        let id = validate_path_segment("table_id", table_id)?;
        self.post_reconcilable(
            "/api/v1/data-tables/{id}/rows",
            &format!("data-tables/{id}/rows"),
            operation_id,
            body,
        )
        .await
    }

    pub async fn upsert_data_table_rows(&self, table_id: &str, body: &Value) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        self.request_json(
            Method::POST,
            "/api/v1/data-tables/{id}/rows/upsert",
            &format!("data-tables/{id}/rows/upsert"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn update_data_table_row(
        &self,
        table_id: &str,
        row_id: &str,
        body: &Value,
    ) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        let rid = validate_path_segment("row_id", row_id)?;
        self.request_json(
            Method::PATCH,
            "/api/v1/data-tables/{id}/rows/{rowId}",
            &format!("data-tables/{id}/rows/{rid}"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_data_table_row(&self, table_id: &str, row_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        let rid = validate_path_segment("row_id", row_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/data-tables/{id}/rows/{rowId}",
            &format!("data-tables/{id}/rows/{rid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn get_data_table_dependencies(&self, table_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("table_id", table_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/data-tables/{id}/dependencies",
            &format!("data-tables/{id}/dependencies"),
            &[],
            None,
            None,
        )
        .await
    }

    // -------------------------------------------------------------------------
    // 6. Projects, Folders, Users, Tags, Variables
    // -------------------------------------------------------------------------

    pub async fn list_projects(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<ProjectResource>> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/projects",
            "projects",
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn get_project(&self, project_id: &str) -> N8nResult<ProjectResource> {
        let id = validate_path_segment("project_id", project_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/projects/{projectId}",
            &format!("projects/{id}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn create_project(
        &self,
        operation_id: &str,
        name: &str,
    ) -> N8nResult<Outcome<ProjectResource>> {
        let body = json!({ "name": name });
        self.post_reconcilable("/api/v1/projects", "projects", operation_id, &body)
            .await
    }

    pub async fn update_project(&self, project_id: &str, name: &str) -> N8nResult<ProjectResource> {
        let id = validate_path_segment("project_id", project_id)?;
        let body = json!({ "name": name });
        self.request_json(
            Method::PUT,
            "/api/v1/projects/{projectId}",
            &format!("projects/{id}"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn delete_project(&self, project_id: &str) -> N8nResult<Value> {
        let id = validate_path_segment("project_id", project_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/projects/{projectId}",
            &format!("projects/{id}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn list_folders(
        &self,
        project_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<FolderResource>> {
        let pid = validate_path_segment("project_id", project_id)?;
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/projects/{projectId}/folders",
            &format!("projects/{pid}/folders"),
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn create_folder(
        &self,
        operation_id: &str,
        project_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<FolderResource>> {
        let pid = validate_path_segment("project_id", project_id)?;
        self.post_reconcilable(
            "/api/v1/projects/{projectId}/folders",
            &format!("projects/{pid}/folders"),
            operation_id,
            body,
        )
        .await
    }

    pub async fn update_folder(
        &self,
        project_id: &str,
        folder_id: &str,
        body: &Value,
    ) -> N8nResult<FolderResource> {
        let pid = validate_path_segment("project_id", project_id)?;
        let fid = validate_path_segment("folder_id", folder_id)?;
        self.request_json(
            Method::PATCH,
            "/api/v1/projects/{projectId}/folders/{folderId}",
            &format!("projects/{pid}/folders/{fid}"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_folder(&self, project_id: &str, folder_id: &str) -> N8nResult<Value> {
        let pid = validate_path_segment("project_id", project_id)?;
        let fid = validate_path_segment("folder_id", folder_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/projects/{projectId}/folders/{folderId}",
            &format!("projects/{pid}/folders/{fid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn list_users(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<UserResource>> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(Method::GET, "/api/v1/users", "users", &query, None, None)
            .await
    }

    pub async fn get_user(&self, id_or_email: &str) -> N8nResult<UserResource> {
        let uid = validate_path_segment("id_or_email", id_or_email)?;
        self.request_json(
            Method::GET,
            "/api/v1/users/{id}",
            &format!("users/{uid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn create_users(
        &self,
        operation_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<Value>> {
        self.post_reconcilable("/api/v1/users", "users", operation_id, body)
            .await
    }

    pub async fn delete_user(&self, user_id: &str) -> N8nResult<Value> {
        let uid = validate_path_segment("user_id", user_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/users/{id}",
            &format!("users/{uid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn change_user_role(&self, user_id: &str, new_role_name: &str) -> N8nResult<Value> {
        let uid = validate_path_segment("user_id", user_id)?;
        let body = json!({ "newRoleName": new_role_name });
        self.request_json(
            Method::PATCH,
            "/api/v1/users/{id}/role",
            &format!("users/{uid}/role"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn list_tags(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<TagResource>> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(Method::GET, "/api/v1/tags", "tags", &query, None, None)
            .await
    }

    pub async fn get_tag(&self, tag_id: &str) -> N8nResult<TagResource> {
        let tid = validate_path_segment("tag_id", tag_id)?;
        self.request_json(
            Method::GET,
            "/api/v1/tags/{id}",
            &format!("tags/{tid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn create_tag(
        &self,
        operation_id: &str,
        name: &str,
    ) -> N8nResult<Outcome<TagResource>> {
        let body = json!({ "name": name });
        self.post_reconcilable("/api/v1/tags", "tags", operation_id, &body)
            .await
    }

    pub async fn update_tag(&self, tag_id: &str, name: &str) -> N8nResult<TagResource> {
        let tid = validate_path_segment("tag_id", tag_id)?;
        let body = json!({ "name": name });
        self.request_json(
            Method::PUT,
            "/api/v1/tags/{id}",
            &format!("tags/{tid}"),
            &[],
            Some(&body),
            None,
        )
        .await
    }

    pub async fn delete_tag(&self, tag_id: &str) -> N8nResult<TagResource> {
        let tid = validate_path_segment("tag_id", tag_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/tags/{id}",
            &format!("tags/{tid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn list_variables(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> N8nResult<PaginatedList<VariableResource>> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/variables",
            "variables",
            &query,
            None,
            None,
        )
        .await
    }

    pub async fn create_variable(
        &self,
        operation_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<VariableResource>> {
        self.post_reconcilable("/api/v1/variables", "variables", operation_id, body)
            .await
    }

    pub async fn update_variable(
        &self,
        variable_id: &str,
        body: &Value,
    ) -> N8nResult<VariableResource> {
        let vid = validate_path_segment("variable_id", variable_id)?;
        self.request_json(
            Method::PUT,
            "/api/v1/variables/{id}",
            &format!("variables/{vid}"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_variable(&self, variable_id: &str) -> N8nResult<Value> {
        let vid = validate_path_segment("variable_id", variable_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/variables/{id}",
            &format!("variables/{vid}"),
            &[],
            None,
            None,
        )
        .await
    }

    // -------------------------------------------------------------------------
    // 7. Audit, Packages, Source Control, Promotions, Policies, Settings, Roles, Insights
    // -------------------------------------------------------------------------

    pub async fn generate_audit(&self, categories: Option<&[String]>) -> N8nResult<Value> {
        let body = categories.map(|cats| json!({ "additionalOptions": { "categories": cats } }));
        let raw: Value = self
            .request_json(
                Method::POST,
                "/api/v1/audit",
                "audit",
                &[],
                body.as_ref(),
                None,
            )
            .await?;
        Ok(redact_json_value(&raw))
    }

    pub async fn list_community_packages(&self) -> N8nResult<Value> {
        self.request_json(
            Method::GET,
            "/api/v1/community-packages",
            "community-packages",
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn install_community_package(
        &self,
        operation_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<Value>> {
        self.post_reconcilable(
            "/api/v1/community-packages",
            "community-packages",
            operation_id,
            body,
        )
        .await
    }

    pub async fn update_community_package(
        &self,
        package_name: &str,
        body: &Value,
    ) -> N8nResult<Value> {
        let pkg = validate_path_segment("package_name", package_name)?;
        self.request_json(
            Method::PATCH,
            "/api/v1/community-packages/{name}",
            &format!("community-packages/{pkg}"),
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn uninstall_community_package(&self, package_name: &str) -> N8nResult<Value> {
        let pkg = validate_path_segment("package_name", package_name)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/community-packages/{name}",
            &format!("community-packages/{pkg}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn list_n8n_packages(&self) -> N8nResult<Value> {
        self.request_json(
            Method::GET,
            "/api/v1/n8n-packages",
            "n8n-packages",
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn export_n8n_package(&self, body: &Value) -> N8nResult<Value> {
        self.request_json(
            Method::POST,
            "/api/v1/n8n-packages/export",
            "n8n-packages/export",
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn import_n8n_package(&self, body: &Value) -> N8nResult<Value> {
        self.request_json(
            Method::POST,
            "/api/v1/n8n-packages/import",
            "n8n-packages/import",
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn get_source_control_status(&self) -> N8nResult<Value> {
        self.request_json(
            Method::GET,
            "/api/v1/source-control/status",
            "source-control/status",
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn pull_source_control(&self, body: &Value) -> N8nResult<Value> {
        self.request_json(
            Method::POST,
            "/api/v1/source-control/pull",
            "source-control/pull",
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn push_source_control(&self, body: &Value) -> N8nResult<Value> {
        self.request_json(
            Method::POST,
            "/api/v1/source-control/push",
            "source-control/push",
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn list_promotions(&self) -> N8nResult<Value> {
        self.request_json(
            Method::GET,
            "/api/v1/promotions",
            "promotions",
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn create_promotion(
        &self,
        operation_id: &str,
        body: &Value,
    ) -> N8nResult<Outcome<Value>> {
        self.post_reconcilable("/api/v1/promotions", "promotions", operation_id, body)
            .await
    }

    pub async fn list_node_type_policies(&self) -> N8nResult<Value> {
        self.request_json(
            Method::GET,
            "/api/v1/node-type-policies",
            "node-type-policies",
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn upsert_node_type_policy(&self, body: &Value) -> N8nResult<Value> {
        self.request_json(
            Method::POST,
            "/api/v1/node-type-policies",
            "node-type-policies",
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_node_type_policy(&self, policy_id: &str) -> N8nResult<Value> {
        let pid = validate_path_segment("policy_id", policy_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/node-type-policies/{id}",
            &format!("node-type-policies/{pid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn list_credential_type_policies(&self) -> N8nResult<Value> {
        self.request_json(
            Method::GET,
            "/api/v1/credential-type-policies",
            "credential-type-policies",
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn upsert_credential_type_policy(&self, body: &Value) -> N8nResult<Value> {
        self.request_json(
            Method::POST,
            "/api/v1/credential-type-policies",
            "credential-type-policies",
            &[],
            Some(body),
            None,
        )
        .await
    }

    pub async fn delete_credential_type_policy(&self, policy_id: &str) -> N8nResult<Value> {
        let pid = validate_path_segment("policy_id", policy_id)?;
        self.request_json(
            Method::DELETE,
            "/api/v1/credential-type-policies/{id}",
            &format!("credential-type-policies/{pid}"),
            &[],
            None,
            None,
        )
        .await
    }

    pub async fn get_settings(&self, section: Option<&str>) -> N8nResult<Value> {
        let (tpl, sub) = if let Some(sec) = section {
            let clean = validate_path_segment("section", sec)?;
            ("/api/v1/settings/{section}", format!("settings/{clean}"))
        } else {
            ("/api/v1/settings", "settings".to_owned())
        };
        let raw: Value = self
            .request_json(Method::GET, tpl, &sub, &[], None, None)
            .await?;
        Ok(redact_json_value(&raw))
    }

    pub async fn update_settings(&self, section: &str, body: &Value) -> N8nResult<Value> {
        let clean = validate_path_segment("section", section)?;
        let raw: Value = self
            .request_json(
                Method::PATCH,
                "/api/v1/settings/{section}",
                &format!("settings/{clean}"),
                &[],
                Some(body),
                None,
            )
            .await?;
        Ok(redact_json_value(&raw))
    }

    pub async fn list_roles(&self) -> N8nResult<Value> {
        self.request_json(Method::GET, "/api/v1/roles", "roles", &[], None, None)
            .await
    }

    pub async fn get_insights_summary(&self, date_range: Option<&str>) -> N8nResult<Value> {
        let mut query = Vec::new();
        if let Some(dr) = date_range {
            query.push(("dateRange", dr.to_owned()));
        }
        self.request_json(
            Method::GET,
            "/api/v1/insights/summary",
            "insights/summary",
            &query,
            None,
            None,
        )
        .await
    }
}

fn build_list_query(params: &ListQueryParams) -> Vec<(&'static str, String)> {
    let mut query = Vec::new();
    if let Some(limit) = params.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(ref cursor) = params.cursor {
        query.push(("cursor", cursor.clone()));
    }
    if let Some(active) = params.active {
        query.push(("active", active.to_string()));
    }
    if let Some(ref tags) = params.tags {
        query.push(("tags", tags.clone()));
    }
    if let Some(ref name) = params.name {
        query.push(("name", name.clone()));
    }
    if let Some(ref project_id) = params.project_id {
        query.push(("projectId", project_id.clone()));
    }
    if let Some(exclude) = params.exclude_pinned_data {
        query.push(("excludePinnedData", exclude.to_string()));
    }
    query
}

fn extract_safe_error_message(body_bytes: &[u8], fallback: &str) -> String {
    if body_bytes.is_empty() {
        return redact_str(fallback);
    }
    if let Ok(val) = serde_json::from_slice::<Value>(body_bytes)
        && let Some(msg) = val
            .get("message")
            .or_else(|| val.get("error"))
            .and_then(Value::as_str)
    {
        let bounded: String = msg.chars().take(512).collect();
        return redact_str(&bounded);
    }
    let text = String::from_utf8_lossy(body_bytes);
    let bounded: String = text.chars().take(512).collect();
    redact_str(&bounded)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use http::Method;
    use n8n_types::{N8nError, SecretValue};
    use serde_json::json;

    use crate::idempotency::{IdempotencyStore, canonical_json_bytes};
    use crate::ssrf::{
        SsrfPolicy, normalize_and_validate_url, validate_ip_address, validate_path_segment,
    };

    #[test]
    fn ssrf_blocks_cleartext_http_metadata_loopback_and_private_ips_by_default() {
        let strict = SsrfPolicy::default();

        // Cleartext HTTP rejected even for public host
        assert!(matches!(
            normalize_and_validate_url("http://staging-n8n.example.internal", &strict),
            Err(N8nError::SsrfBlocked { .. })
        ));

        // Loopback rejected when allow_loopback_http is false
        assert!(matches!(
            normalize_and_validate_url("https://127.0.0.1:5678", &strict),
            Err(N8nError::SsrfBlocked { .. })
        ));

        // Cloud metadata 169.254.169.254 rejected EVEN when trust_configured_private_host is true!
        let permissive_private = SsrfPolicy {
            allow_loopback_http: true,
            trust_configured_private_host: true,
            trusted_private_ips: vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        };
        assert!(matches!(
            normalize_and_validate_url(
                "https://169.254.169.254/latest/meta-data",
                &permissive_private
            ),
            Err(N8nError::SsrfBlocked { .. })
        ));

        // IPv4-mapped IPv6 metadata ::ffff:169.254.169.254 is also blocked!
        let mapped_meta = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
        assert!(matches!(
            validate_ip_address(
                IpAddr::V6(mapped_meta),
                "mapped_imds",
                true,
                &permissive_private
            ),
            Err(N8nError::SsrfBlocked { .. })
        ));

        // RFC1918 blocked by default, permitted ONLY when trust_configured_private_host is true on pinned host
        assert!(matches!(
            normalize_and_validate_url("https://10.20.30.40:5678", &strict),
            Err(N8nError::SsrfBlocked { .. })
        ));
        assert!(
            normalize_and_validate_url("https://10.20.30.40:5678", &permissive_private).is_ok()
        );

        // IPv6 ULA blocked unless trusted
        let ula: Ipv6Addr = "fd12:3456:789a::1".parse().expect("valid ipv6");
        assert!(validate_ip_address(IpAddr::V6(ula), "ula", true, &strict).is_err());
        assert!(validate_ip_address(IpAddr::V6(ula), "ula", true, &permissive_private).is_ok());
    }

    #[test]
    fn path_segment_validator_blocks_traversal_and_encoded_slashes() {
        assert!(validate_path_segment("workflow_id", "../admin").is_err());
        assert!(validate_path_segment("workflow_id", "wf%2Fsecret").is_err());
        assert_eq!(
            validate_path_segment("workflow_id", "wf_abc-123").expect("valid id"),
            "wf_abc-123"
        );
    }

    #[test]
    fn idempotency_store_reuses_key_on_identical_canonical_json_and_refuses_drift() {
        let store = IdempotencyStore::new("staging");
        let body_a = json!({ "name": "Demo", "nodes": [], "active": false });
        let body_b_reordered = json!({ "active": false, "nodes": [], "name": "Demo" });
        let body_c_changed = json!({ "active": true, "nodes": [], "name": "Demo" });

        assert_eq!(
            canonical_json_bytes(&body_a).expect("canonical a"),
            canonical_json_bytes(&body_b_reordered).expect("canonical b")
        );

        // Ignored on GET/PUT/DELETE
        assert_eq!(
            store
                .resolve_key(&Method::PUT, "/api/v1/workflows/{id}", "op1", Some(&body_a))
                .expect("put ignored"),
            None
        );

        let key1 = store
            .resolve_key(
                &Method::POST,
                "/api/v1/workflows",
                "op_create_1",
                Some(&body_a),
            )
            .expect("post key 1")
            .expect("some key");
        let key2 = store
            .resolve_key(
                &Method::POST,
                "/api/v1/workflows",
                "op_create_1",
                Some(&body_b_reordered),
            )
            .expect("post key 2")
            .expect("some key");
        assert_eq!(key1, key2);

        // Payload drift on same operation_id must fail closed!
        let drift = store.resolve_key(
            &Method::POST,
            "/api/v1/workflows",
            "op_create_1",
            Some(&body_c_changed),
        );
        assert!(matches!(drift, Err(N8nError::Validation422 { .. })));

        let s1 = SecretValue::new("key_one");
        let s2 = SecretValue::new("key_one");
        assert!(s1.matches_secret(&s2));
    }
}
