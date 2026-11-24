//! Strict operation response envelope (`ToolEnvelope<T>`) and risk/routing enums (V2 Section 4).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::redact::{redact_json_value, redact_str};

/// Output verbosity level supported across MCP read/inspection tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DetailLevel {
    Minimal,
    #[default]
    Standard,
    Full,
}

/// Logical environment classification for an n8n instance profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentKind {
    Development,
    #[default]
    Staging,
    Production,
}

impl EnvironmentKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

/// Operation risk classification (`R0..R4`) enforced by `n8n-policy` (V2 Section 5).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum RiskLevel {
    /// Read-only metadata search, schema lookup, redacted diagnostics.
    R0,
    /// Safe local preparation: offline validation, dry-run diff, sanitized fixture generation.
    R1,
    /// Draft write: create or edit an inactive workflow draft in non-production.
    R2,
    /// Real effects: real execution, retry, data-table write, publish/unpublish, transfer.
    R3,
    /// Destructive/admin: delete, bulk stop, community package install, RBAC/settings, prod publish.
    R4,
}

impl RiskLevel {
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(self, Self::R2 | Self::R3 | Self::R4)
    }

    #[must_use]
    pub const fn requires_explicit_confirmation(self) -> bool {
        matches!(self, Self::R3 | Self::R4)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::R0 => "R0_read",
            Self::R1 => "R1_safe_prepare",
            Self::R2 => "R2_draft_write",
            Self::R3 => "R3_real_effects",
            Self::R4 => "R4_destructive_or_admin",
        }
    }
}

/// High-level operation status reported in `ToolEnvelope<T>`.
///
/// Never claim `Success` solely from HTTP 200 when native MCP reports skipped operations,
/// deferred publication, or nonterminal execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Success,
    Preview,
    Blocked,
    Unsupported,
    Conflict,
    Partial,
    Error,
}

/// Policy and permission decision attached to every envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Allowed,
    NeedsApproval,
    Denied,
    Unknown,
}

/// Underlying execution/inspection route selected for the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RouteUsed {
    NativeMcp,
    PublicApi,
    Local,
    Unsupported,
}

impl RouteUsed {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeMcp => "native_mcp",
            Self::PublicApi => "public_api",
            Self::Local => "local",
            Self::Unsupported => "unsupported",
        }
    }
}

///Bounded redacted diff summary attached to mutation previews and commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoundedDiffSummary {
    pub summary: String,
    #[serde(default)]
    pub changed_nodes: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
}

impl BoundedDiffSummary {
    #[must_use]
    pub fn redacted(summary: impl AsRef<str>, changed_nodes: Vec<String>, truncated: bool) -> Self {
        Self {
            summary: redact_str(summary.as_ref()),
            changed_nodes: changed_nodes.into_iter().map(|n| redact_str(&n)).collect(),
            truncated,
        }
    }
}

/// Post-operation verification state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Inconclusive,
    #[default]
    NotRun,
}

/// Verification report confirming whether saved/live state was verified by read-back.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub state: VerificationState,
    #[serde(default)]
    pub details: Vec<String>,
}

impl VerificationReport {
    #[must_use]
    pub fn not_run() -> Self {
        Self {
            state: VerificationState::NotRun,
            details: Vec::new(),
        }
    }

    #[must_use]
    pub fn verified(details: impl IntoIterator<Item = String>) -> Self {
        Self {
            state: VerificationState::Verified,
            details: details.into_iter().map(|d| redact_str(&d)).collect(),
        }
    }

    #[must_use]
    pub fn inconclusive(details: impl IntoIterator<Item = String>) -> Self {
        Self {
            state: VerificationState::Inconclusive,
            details: details.into_iter().map(|d| redact_str(&d)).collect(),
        }
    }
}

/// Canonical V2 Section 4 response envelope returned by all 24 logical MCP tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolEnvelope<T> {
    pub status: OperationStatus,
    pub instance: String,
    pub operation_id: String,
    pub workflow_id: Option<String>,
    pub action: String,
    pub permission: PermissionDecision,
    pub route_used: RouteUsed,
    pub version_before: Option<String>,
    pub version_after: Option<String>,
    pub active_version_id: Option<String>,
    pub changed: bool,
    pub warnings: Vec<String>,
    pub data: Option<T>,
    pub diff: Option<BoundedDiffSummary>,
    pub verification: VerificationReport,
    pub next_actions: Vec<String>,
    pub audit_id: String,
}

impl<T> ToolEnvelope<T> {
    /// Creates a new envelope with freshly generated opaque `operation_id` and `audit_id`.
    #[must_use]
    pub fn new(
        status: OperationStatus,
        instance: impl Into<String>,
        action: impl Into<String>,
        permission: PermissionDecision,
        route_used: RouteUsed,
    ) -> Self {
        Self {
            status,
            instance: redact_str(&instance.into()),
            operation_id: format!("op_{}", Uuid::now_v7().simple()),
            workflow_id: None,
            action: redact_str(&action.into()),
            permission,
            route_used,
            version_before: None,
            version_after: None,
            active_version_id: None,
            changed: false,
            warnings: Vec::new(),
            data: None,
            diff: None,
            verification: VerificationReport::not_run(),
            next_actions: Vec::new(),
            audit_id: format!("aud_{}", Uuid::now_v7().simple()),
        }
    }

    #[must_use]
    pub fn with_workflow_id(mut self, workflow_id: Option<String>) -> Self {
        self.workflow_id = workflow_id.map(|id| redact_str(&id));
        self
    }

    #[must_use]
    pub fn with_versions(
        mut self,
        version_before: Option<String>,
        version_after: Option<String>,
        active_version_id: Option<String>,
    ) -> Self {
        self.version_before = version_before.map(|v| redact_str(&v));
        self.version_after = version_after.map(|v| redact_str(&v));
        self.active_version_id = active_version_id.map(|v| redact_str(&v));
        self
    }

    #[must_use]
    pub const fn with_changed(mut self, changed: bool) -> Self {
        self.changed = changed;
        self
    }

    #[must_use]
    pub fn with_data(mut self, data: T) -> Self {
        self.data = Some(data);
        self
    }

    #[must_use]
    pub fn with_warning(mut self, warning: impl AsRef<str>) -> Self {
        self.warnings.push(redact_str(warning.as_ref()));
        self
    }

    #[must_use]
    pub fn with_warnings(mut self, warnings: impl IntoIterator<Item = String>) -> Self {
        self.warnings
            .extend(warnings.into_iter().map(|w| redact_str(&w)));
        self
    }

    #[must_use]
    pub fn with_diff(mut self, diff: BoundedDiffSummary) -> Self {
        self.diff = Some(diff);
        self
    }

    #[must_use]
    pub fn with_verification(mut self, verification: VerificationReport) -> Self {
        self.verification = verification;
        self
    }

    #[must_use]
    pub fn with_next_actions(mut self, next_actions: impl IntoIterator<Item = String>) -> Self {
        self.next_actions
            .extend(next_actions.into_iter().map(|a| redact_str(&a)));
        self
    }
}

impl<T: Serialize> ToolEnvelope<T> {
    /// Serializes the envelope into a `serde_json::Value` and runs recursive secret redaction
    /// across the entire structure (including `data`) before returning it to any MCP client or log.
    pub fn to_redacted_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let raw = serde_json::to_value(self)?;
        Ok(redact_json_value(&raw))
    }

    /// Serializes the envelope to a compact redacted JSON string.
    pub fn to_redacted_json_string(&self) -> Result<String, serde_json::Error> {
        let redacted = self.to_redacted_value()?;
        serde_json::to_string(&redacted)
    }

    /// Serializes the envelope to a pretty-printed redacted JSON string.
    pub fn to_redacted_json_string_pretty(&self) -> Result<String, serde_json::Error> {
        let redacted = self.to_redacted_value()?;
        serde_json::to_string_pretty(&redacted)
    }
}
