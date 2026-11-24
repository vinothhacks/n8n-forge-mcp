//! Typed error hierarchy (`N8nError`) with fail-closed semantics and automatic secret redaction.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::envelope::{OperationStatus, PermissionDecision, RiskLevel, RouteUsed, ToolEnvelope};
use crate::redact::redact_str;

/// Standard result alias across `n8n-rs-mcp` crates.
pub type N8nResult<T> = Result<T, N8nError>;

/// Structured, fail-closed error hierarchy covering HTTP, SSRF, payload, policy, and capability errors.
///
/// All message strings must pass through [`redact_str`] before display or serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum N8nError {
    /// HTTP 401: missing, invalid, or expired API key / bearer token.
    #[error("[401_UNAUTHENTICATED] instance={instance}: {message}")]
    Unauthenticated401 { instance: String, message: String },

    /// HTTP 403: insufficient scopes, project role, or instance feature/license restriction.
    /// Fail-closed: NEVER downgrade to an alternate route on 403.
    #[error(
        "[403_FORBIDDEN] instance={instance} scope_or_resource={scope_or_resource:?}: {message}"
    )]
    Forbidden403 {
        instance: String,
        scope_or_resource: Option<String>,
        message: String,
    },

    /// HTTP 404: absent endpoint OR concealed resource (404 alone never proves version absence).
    #[error("[404_NOT_FOUND_OR_CONCEALED] instance={instance} resource={resource}: {message}")]
    NotFoundOrConcealed404 {
        instance: String,
        resource: String,
        message: String,
    },

    /// HTTP 409: version, publish, or state conflict returned by server.
    #[error("[409_CONFLICT] instance={instance} resource={resource:?}: {message}")]
    Conflict409 {
        instance: String,
        resource: Option<String>,
        message: String,
    },

    /// HTTP 400 / 422: request schema, parameter, or idempotency payload validation failure.
    #[error("[422_VALIDATION] instance={instance}: {message}")]
    Validation422 {
        instance: String,
        details: Vec<String>,
        message: String,
    },

    /// HTTP 429: global or per-endpoint read/write rate-limit bucket exhausted.
    #[error(
        "[429_RATE_LIMITED] instance={instance} bucket={bucket:?} retry_after_ms={retry_after_ms:?}: {message}"
    )]
    RateLimited429 {
        instance: String,
        bucket: Option<String>,
        retry_after_ms: Option<u64>,
        message: String,
    },

    /// Transport timeout or connection drop during an operation.
    /// When `needs_reconcile` is `true` (mutating request), callers MUST perform read-after-write
    /// reconciliation instead of blind retry.
    #[error(
        "[TIMEOUT_UNKNOWN_OUTCOME] instance={instance} {method} {path_template} needs_reconcile={needs_reconcile}: {message}"
    )]
    TimeoutUnknownOutcome {
        instance: String,
        method: String,
        path_template: String,
        needs_reconcile: bool,
        message: String,
    },

    /// Blocked by URL/DNS/IP SSRF or cross-origin redirect policy.
    #[error("[SSRF_BLOCKED] target={url_redacted}: {reason}")]
    SsrfBlocked {
        url_redacted: String,
        reason: String,
    },

    /// Compressed or decompressed response exceeded configured byte budget.
    #[error(
        "[PAYLOAD_TOO_LARGE] phase={phase} observed_bytes={observed_bytes} limit_bytes={limit_bytes}"
    )]
    PayloadTooLarge {
        limit_bytes: u64,
        observed_bytes: u64,
        phase: String,
    },

    /// Blocked by server-enforced `n8n-policy` (`PolicyMode`, risk gate, batch cap, or receipt check).
    #[error("[POLICY_BLOCKED] action={action} risk={risk:?} policy={policy_mode}: {reason}")]
    PolicyBlocked {
        action: String,
        risk: RiskLevel,
        policy_mode: String,
        reason: String,
        approval_hint: Option<String>,
    },

    /// Feature or endpoint is not advertised or supported on the connected n8n instance.
    #[error("[UNSUPPORTED_CAPABILITY] instance={instance} operation={operation}: {reason}")]
    UnsupportedCapability {
        instance: String,
        operation: String,
        reason: String,
        prerequisite: Option<String>,
    },

    /// Configuration or URL validation failure.
    #[error("[CONFIG_ERROR] {message}")]
    Config { message: String },

    /// Sanitized transport, TLS, or remote 5xx error.
    #[error("[TRANSPORT_ERROR] instance={instance} status={status_code:?}: {message}")]
    Transport {
        instance: String,
        status_code: Option<u16>,
        message: String,
    },

    /// Sanitized serialization/deserialization or protocol framing error.
    #[error("[PROTOCOL_ERROR] {message}")]
    Protocol { message: String },
}

impl N8nError {
    #[must_use]
    pub fn unauthenticated(instance: impl Into<String>, message: impl AsRef<str>) -> Self {
        Self::Unauthenticated401 {
            instance: redact_str(&instance.into()),
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn forbidden(
        instance: impl Into<String>,
        scope_or_resource: Option<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::Forbidden403 {
            instance: redact_str(&instance.into()),
            scope_or_resource: scope_or_resource.map(|s| redact_str(&s)),
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn not_found_or_concealed(
        instance: impl Into<String>,
        resource: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::NotFoundOrConcealed404 {
            instance: redact_str(&instance.into()),
            resource: redact_str(&resource.into()),
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn conflict(
        instance: impl Into<String>,
        resource: Option<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::Conflict409 {
            instance: redact_str(&instance.into()),
            resource: resource.map(|r| redact_str(&r)),
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn validation(
        instance: impl Into<String>,
        details: impl IntoIterator<Item = String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::Validation422 {
            instance: redact_str(&instance.into()),
            details: details.into_iter().map(|d| redact_str(&d)).collect(),
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn rate_limited(
        instance: impl Into<String>,
        bucket: Option<String>,
        retry_after_ms: Option<u64>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::RateLimited429 {
            instance: redact_str(&instance.into()),
            bucket: bucket.map(|b| redact_str(&b)),
            retry_after_ms,
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn timeout_unknown(
        instance: impl Into<String>,
        method: impl Into<String>,
        path_template: impl Into<String>,
        needs_reconcile: bool,
        message: impl AsRef<str>,
    ) -> Self {
        Self::TimeoutUnknownOutcome {
            instance: redact_str(&instance.into()),
            method: redact_str(&method.into()),
            path_template: redact_str(&path_template.into()),
            needs_reconcile,
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn ssrf_blocked(url_redacted: impl AsRef<str>, reason: impl AsRef<str>) -> Self {
        Self::SsrfBlocked {
            url_redacted: redact_str(url_redacted.as_ref()),
            reason: redact_str(reason.as_ref()),
        }
    }

    #[must_use]
    pub fn payload_too_large(
        limit_bytes: u64,
        observed_bytes: u64,
        phase: impl Into<String>,
    ) -> Self {
        Self::PayloadTooLarge {
            limit_bytes,
            observed_bytes,
            phase: redact_str(&phase.into()),
        }
    }

    #[must_use]
    pub fn policy_blocked(
        action: impl Into<String>,
        risk: RiskLevel,
        policy_mode: impl Into<String>,
        reason: impl AsRef<str>,
        approval_hint: Option<String>,
    ) -> Self {
        Self::PolicyBlocked {
            action: redact_str(&action.into()),
            risk,
            policy_mode: redact_str(&policy_mode.into()),
            reason: redact_str(reason.as_ref()),
            approval_hint: approval_hint.map(|h| redact_str(&h)),
        }
    }

    #[must_use]
    pub fn unsupported(
        instance: impl Into<String>,
        operation: impl Into<String>,
        reason: impl AsRef<str>,
        prerequisite: Option<String>,
    ) -> Self {
        Self::UnsupportedCapability {
            instance: redact_str(&instance.into()),
            operation: redact_str(&operation.into()),
            reason: redact_str(reason.as_ref()),
            prerequisite: prerequisite.map(|p| redact_str(&p)),
        }
    }

    #[must_use]
    pub fn config(message: impl AsRef<str>) -> Self {
        Self::Config {
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn transport(
        instance: impl Into<String>,
        status_code: Option<u16>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::Transport {
            instance: redact_str(&instance.into()),
            status_code,
            message: redact_str(message.as_ref()),
        }
    }

    #[must_use]
    pub fn protocol(message: impl AsRef<str>) -> Self {
        Self::Protocol {
            message: redact_str(message.as_ref()),
        }
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Unauthenticated401 { .. } => "UNAUTHENTICATED_401",
            Self::Forbidden403 { .. } => "FORBIDDEN_403",
            Self::NotFoundOrConcealed404 { .. } => "NOT_FOUND_OR_CONCEALED_404",
            Self::Conflict409 { .. } => "CONFLICT_409",
            Self::Validation422 { .. } => "VALIDATION_422",
            Self::RateLimited429 { .. } => "RATE_LIMITED_429",
            Self::TimeoutUnknownOutcome { .. } => "TIMEOUT_UNKNOWN_OUTCOME",
            Self::SsrfBlocked { .. } => "SSRF_BLOCKED",
            Self::PayloadTooLarge { .. } => "PAYLOAD_TOO_LARGE",
            Self::PolicyBlocked { .. } => "POLICY_BLOCKED",
            Self::UnsupportedCapability { .. } => "UNSUPPORTED_CAPABILITY",
            Self::Config { .. } => "CONFIG_ERROR",
            Self::Transport { .. } => "TRANSPORT_ERROR",
            Self::Protocol { .. } => "PROTOCOL_ERROR",
        }
    }

    /// Fail-closed check: returns `false` whenever an error represents denied authorization,
    /// invalid authentication, policy denial, or SSRF block—preventing route downgrade!
    #[must_use]
    pub const fn allows_route_fallback(&self) -> bool {
        match self {
            Self::Unauthenticated401 { .. }
            | Self::Forbidden403 { .. }
            | Self::PolicyBlocked { .. }
            | Self::SsrfBlocked { .. }
            | Self::Conflict409 { .. }
            | Self::Validation422 { .. }
            | Self::PayloadTooLarge { .. }
            | Self::TimeoutUnknownOutcome { .. } => false,
            Self::UnsupportedCapability { .. }
            | Self::NotFoundOrConcealed404 { .. }
            | Self::RateLimited429 { .. }
            | Self::Config { .. }
            | Self::Transport { .. }
            | Self::Protocol { .. } => true,
        }
    }

    #[must_use]
    pub const fn to_operation_status(&self) -> OperationStatus {
        match self {
            Self::PolicyBlocked { .. } | Self::Forbidden403 { .. } | Self::SsrfBlocked { .. } => {
                OperationStatus::Blocked
            }
            Self::UnsupportedCapability { .. } => OperationStatus::Unsupported,
            Self::Conflict409 { .. } => OperationStatus::Conflict,
            Self::TimeoutUnknownOutcome {
                needs_reconcile: true,
                ..
            } => OperationStatus::Partial,
            Self::Unauthenticated401 { .. }
            | Self::NotFoundOrConcealed404 { .. }
            | Self::Validation422 { .. }
            | Self::RateLimited429 { .. }
            | Self::PayloadTooLarge { .. }
            | Self::TimeoutUnknownOutcome {
                needs_reconcile: false,
                ..
            }
            | Self::Config { .. }
            | Self::Transport { .. }
            | Self::Protocol { .. } => OperationStatus::Error,
        }
    }

    #[must_use]
    pub const fn to_permission_decision(&self) -> PermissionDecision {
        match self {
            Self::Forbidden403 { .. }
            | Self::Unauthenticated401 { .. }
            | Self::SsrfBlocked { .. } => PermissionDecision::Denied,
            Self::PolicyBlocked {
                approval_hint: Some(_),
                ..
            } => PermissionDecision::NeedsApproval,
            Self::PolicyBlocked {
                approval_hint: None,
                ..
            } => PermissionDecision::Denied,
            Self::NotFoundOrConcealed404 { .. } | Self::UnsupportedCapability { .. } => {
                PermissionDecision::Unknown
            }
            Self::Conflict409 { .. }
            | Self::Validation422 { .. }
            | Self::RateLimited429 { .. }
            | Self::TimeoutUnknownOutcome { .. }
            | Self::PayloadTooLarge { .. }
            | Self::Config { .. }
            | Self::Transport { .. }
            | Self::Protocol { .. } => PermissionDecision::Allowed,
        }
    }

    /// Converts this error into a sanitized `ToolEnvelope<serde_json::Value>` suitable for MCP output.
    #[must_use]
    pub fn into_envelope(
        self,
        instance: impl Into<String>,
        action: impl Into<String>,
        route_used: RouteUsed,
    ) -> ToolEnvelope<serde_json::Value> {
        let status = self.to_operation_status();
        let permission = self.to_permission_decision();
        let mut next_actions = Vec::new();
        if let Self::PolicyBlocked {
            approval_hint: Some(ref hint),
            ..
        } = self
        {
            next_actions.push(hint.clone());
        }
        if let Self::TimeoutUnknownOutcome {
            needs_reconcile: true,
            ..
        } = self
        {
            next_actions.push(
                "Run read-after-write reconciliation (`n8n-rs-mcp reconcile` or `n8n_workflows.get`) before retrying."
                    .to_owned(),
            );
        }
        if let Self::UnsupportedCapability {
            prerequisite: Some(ref prereq),
            ..
        } = self
        {
            next_actions.push(prereq.clone());
        }

        let err_payload = serde_json::json!({
            "errorCode": self.error_code(),
            "message": redact_str(&self.to_string()),
            "detail": serde_json::to_value(&self).unwrap_or(serde_json::Value::Null),
        });

        ToolEnvelope::new(status, instance, action, permission, route_used)
            .with_warning(self.to_string())
            .with_data(crate::redact::redact_json_value(&err_payload))
            .with_next_actions(next_actions)
    }
}
