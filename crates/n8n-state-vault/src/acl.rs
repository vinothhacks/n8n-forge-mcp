//! OS-specific per-user protected state directory (`%LOCALAPPDATA%\n8n-rs-mcp` on Windows,
//! `$XDG_DATA_HOME/n8n-rs-mcp` or `~/Library/Application Support/n8n-rs-mcp` elsewhere)
//! with current-user-only Windows DACL (`icacls` direct argv) and Unix `0700`/`0600` enforcement.

use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::sync::OnceLock;

use n8n_types::{N8nError, N8nResult, redact_str};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Health and ACL posture summary for the per-user state vault directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub directory_configured: bool,
    pub directory_exists: bool,
    pub writable: bool,
    #[serde(default)]
    pub acl_restricted: bool,
    pub note: String,
}

/// Detailed read-only ACL inspection result for a state directory or file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AclInspection {
    pub inspected: bool,
    pub restricted_to_current_user: bool,
    pub detail: String,
}

/// Resolves the OS-specific per-user protected state directory (`%LOCALAPPDATA%\n8n-rs-mcp` on Windows).
#[must_use]
pub fn default_state_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(local_app_data).join("n8n-rs-mcp"));
        }
    }
    dirs::data_local_dir().map(|base| base.join("n8n-rs-mcp"))
}

/// Non-mutating health & ACL check for the per-user state directory.
#[must_use]
pub fn check_user_state_dir(override_dir: Option<&Path>) -> VaultStatus {
    let target = override_dir
        .map(Path::to_path_buf)
        .or_else(default_state_dir);
    let Some(dir) = target else {
        return VaultStatus {
            directory_configured: false,
            directory_exists: false,
            writable: false,
            acl_restricted: false,
            note: "No per-user local data directory resolved; memory-only state mode.".to_owned(),
        };
    };

    let exists = dir.exists();
    let writable = if exists {
        dir.metadata()
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    } else {
        dir.parent()
            .and_then(|p| p.metadata().ok())
            .map(|m| !m.permissions().readonly())
            .unwrap_or(true)
    };

    let acl_restricted = if exists {
        inspect_path_acl(&dir).restricted_to_current_user
    } else {
        false
    };

    let note = if exists && acl_restricted {
        "Per-user state directory verified with current-user-only ACLs (no secrets written)."
            .to_owned()
    } else if exists {
        "Per-user state directory exists (ACL hardening pending on next vault open; no secrets written)."
            .to_owned()
    } else {
        "Per-user state directory configured (will be created with current-user-only ACLs on demand)."
            .to_owned()
    };

    VaultStatus {
        directory_configured: true,
        directory_exists: exists,
        writable,
        acl_restricted,
        note,
    }
}

/// Creates `override_dir` (or [`default_state_dir`]) if absent and applies current-user-only OS ACLs.
pub fn ensure_protected_state_dir(
    override_dir: Option<&Path>,
) -> N8nResult<(PathBuf, VaultStatus)> {
    let dir = override_dir
        .map(Path::to_path_buf)
        .or_else(default_state_dir)
        .ok_or_else(|| {
            N8nError::config("unable to resolve per-user state directory (%LOCALAPPDATA% / data_local_dir unavailable)")
        })?;

    fs::create_dir_all(&dir).map_err(|e| {
        N8nError::config(format!(
            "failed creating state vault directory: {}",
            redact_str(&e.to_string())
        ))
    })?;

    let applied = protect_state_dir(&dir)?;
    let status = check_user_state_dir(Some(&dir));
    let final_status = VaultStatus {
        acl_restricted: status.acl_restricted || applied,
        ..status
    };
    Ok((dir, final_status))
}

/// Enforces current-user-only directory permissions (`icacls` DACL on Windows, `0700` on Unix).
pub fn protect_state_dir(dir: &Path) -> N8nResult<bool> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| {
            N8nError::config(format!(
                "failed creating protected directory: {}",
                redact_str(&e.to_string())
            ))
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, perms).map_err(|e| {
            N8nError::config(format!(
                "failed setting Unix 0700 mode on state directory: {}",
                redact_str(&e.to_string())
            ))
        })?;
        Ok(true)
    }

    #[cfg(windows)]
    {
        apply_windows_icacls(dir, true)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Ok(false)
    }
}

/// Enforces current-user-only file permissions (`icacls` DACL on Windows, `0600` on Unix).
pub fn protect_state_file(file_path: &Path) -> N8nResult<bool> {
    if !file_path.exists() {
        return Ok(false);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(file_path, perms).map_err(|e| {
            N8nError::config(format!(
                "failed setting Unix 0600 mode on state file: {}",
                redact_str(&e.to_string())
            ))
        })?;
        Ok(true)
    }

    #[cfg(windows)]
    {
        apply_windows_icacls(file_path, false)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = file_path;
        Ok(false)
    }
}

/// Performs a read-only inspection of OS ACLs on `path` (`icacls` argv check on Windows, mode bits on Unix).
#[must_use]
pub fn inspect_path_acl(path: &Path) -> AclInspection {
    if !path.exists() {
        return AclInspection {
            inspected: false,
            restricted_to_current_user: false,
            detail: "path does not exist".to_owned(),
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return match path.metadata() {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                let restricted = (mode & 0o077) == 0;
                AclInspection {
                    inspected: true,
                    restricted_to_current_user: restricted,
                    detail: format!("unix mode {mode:04o}"),
                }
            }
            Err(e) => AclInspection {
                inspected: false,
                restricted_to_current_user: false,
                detail: redact_str(&e.to_string()),
            },
        };
    }

    #[cfg(windows)]
    {
        inspect_windows_icacls(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        AclInspection {
            inspected: false,
            restricted_to_current_user: false,
            detail: "ACL inspection unsupported on target OS".to_owned(),
        }
    }
}

#[cfg(windows)]
fn cached_current_windows_principal() -> Option<String> {
    static PRINCIPAL: OnceLock<Option<String>> = OnceLock::new();
    PRINCIPAL
        .get_or_init(|| {
            // Prefer universal SID (`*S-1-5-21-...`) via direct `whoami /user /fo csv /nh` argv.
            if let Ok(output) = Command::new("whoami")
                .args(["/user", "/fo", "csv", "/nh"])
                .output()
                && output.status.success()
            {
                let text = String::from_utf8_lossy(&output.stdout);
                for field in text.trim().split(',') {
                    let trimmed = field.trim().trim_matches('"');
                    if trimmed.starts_with("S-1-") {
                        return Some(format!("*{trimmed}"));
                    }
                }
            }

            // Fallback to `USERDOMAIN\USERNAME` or `USERNAME` if `whoami` is unavailable.
            let user = std::env::var("USERNAME").ok().filter(|s| !s.is_empty())?;
            if let Ok(domain) = std::env::var("USERDOMAIN")
                && !domain.is_empty()
            {
                Some(format!("{domain}\\{user}"))
            } else {
                Some(user)
            }
        })
        .clone()
}

#[cfg(windows)]
fn apply_windows_icacls(path: &Path, is_directory: bool) -> N8nResult<bool> {
    let Some(principal) = cached_current_windows_principal() else {
        tracing::warn!("Could not determine current Windows principal for icacls hardening");
        return Ok(false);
    };

    let user_grant = if is_directory {
        format!("{principal}:(OI)(CI)F")
    } else {
        format!("{principal}:F")
    };
    let system_grant = if is_directory {
        "*S-1-5-18:(OI)(CI)F"
    } else {
        "*S-1-5-18:F"
    };

    let output = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &user_grant, system_grant])
        .output()
        .map_err(|e| {
            N8nError::config(format!(
                "failed invoking icacls for state vault ACL: {}",
                redact_str(&e.to_string())
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(N8nError::config(format!(
            "icacls failed hardening state vault path (exit={:?}): {}",
            output.status.code(),
            redact_str(stderr.trim())
        )));
    }

    Ok(true)
}

#[cfg(windows)]
fn inspect_windows_icacls(path: &Path) -> AclInspection {
    let output = match Command::new("icacls").arg(path).output() {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            return AclInspection {
                inspected: false,
                restricted_to_current_user: false,
                detail: format!("icacls exited with {:?}", out.status.code()),
            };
        }
        Err(e) => {
            return AclInspection {
                inspected: false,
                restricted_to_current_user: false,
                detail: redact_str(&e.to_string()),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let path_str = path.to_string_lossy();
    let mut ace_lines = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed
                .to_ascii_lowercase()
                .starts_with("successfully processed")
        {
            continue;
        }
        let stripped = trimmed
            .strip_prefix(path_str.as_ref())
            .map_or(trimmed, str::trim);
        if !stripped.is_empty() {
            ace_lines.push(stripped.to_ascii_lowercase());
        }
    }

    let has_broad_multi_user_ace = ace_lines.iter().any(|ace| {
        ace.contains("everyone:")
            || ace.contains("builtin\\users:")
            || ace.contains("authenticated users:")
            || ace.contains("s-1-1-0:")
            || ace.contains("s-1-5-32-545:")
            || ace.contains("s-1-5-11:")
    });

    AclInspection {
        inspected: true,
        restricted_to_current_user: !ace_lines.is_empty() && !has_broad_multi_user_ace,
        detail: if has_broad_multi_user_ace {
            "broad multi-user ACE detected (`Users`/`Authenticated Users`/`Everyone`)".to_owned()
        } else {
            "restricted DACL verified (no broad multi-user ACEs)".to_owned()
        },
    }
}
