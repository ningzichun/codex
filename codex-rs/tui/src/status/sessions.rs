use super::rate_limits::RateLimitSnapshotDisplay;
use super::rate_limits::StatusRateLimitData;
use super::rate_limits::StatusRateLimitRow;
use super::rate_limits::StatusRateLimitValue;
use super::rate_limits::compose_rate_limit_data_many;
use super::rate_limits::format_status_limit_summary;
use super::rate_limits::rate_limit_snapshot_display_for_limit;
use chrono::DateTime;
use chrono::Local;
use chrono::Utc;
use codex_core::CodexAuth;
use codex_core::auth::AuthMode;
use codex_core::auth::auth_storage_home;
use codex_core::config::CONFIG_TOML_FILE;
use codex_core::config::Config;
use codex_protocol::account::PlanType;
use codex_protocol::protocol::RateLimitSnapshot;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const RATE_LIMITS_FILE: &str = "rate_limits.json";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LoginSessionKey {
    Legacy,
    Profile(String),
}

#[derive(Debug, Default, Deserialize)]
struct SessionStatusConfigToml {
    model_provider: Option<String>,
    #[serde(default)]
    model_providers: BTreeMap<String, SessionStatusProviderToml>,
    #[serde(default)]
    profiles: BTreeMap<String, SessionStatusProfileToml>,
}

#[derive(Debug, Default, Deserialize)]
struct SessionStatusProfileToml {
    model_provider: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SessionStatusProviderToml {
    name: Option<String>,
    base_url: Option<String>,
}

#[derive(Debug, Clone)]
struct LoginSessionSummary {
    name: String,
    is_active: bool,
    provider: String,
    account: String,
    limits: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRateLimitSnapshot {
    captured_at: DateTime<Utc>,
    snapshot: RateLimitSnapshot,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoredRateLimitSnapshots {
    snapshots: BTreeMap<String, StoredRateLimitSnapshot>,
}

pub(crate) fn persist_active_session_rate_limit_snapshot(
    config: &Config,
    snapshot: &RateLimitSnapshot,
    captured_at: DateTime<Local>,
) {
    let auth_home = auth_storage_home(&config.codex_home, config.active_profile.as_deref());
    let file_path = auth_home.join(RATE_LIMITS_FILE);
    let mut stored = load_stored_rate_limits_file(&file_path).unwrap_or_default();
    let limit_id = snapshot
        .limit_id
        .clone()
        .unwrap_or_else(|| "codex".to_string());
    stored.snapshots.insert(
        limit_id,
        StoredRateLimitSnapshot {
            captured_at: captured_at.with_timezone(&Utc),
            snapshot: snapshot.clone(),
        },
    );

    if let Some(parent) = file_path.parent()
        && let Err(err) = fs::create_dir_all(parent)
    {
        tracing::debug!(error = ?err, path = %parent.display(), "failed to create rate limit directory");
        return;
    }

    match serde_json::to_vec_pretty(&stored) {
        Ok(json) => {
            if let Err(err) = fs::write(&file_path, json) {
                tracing::debug!(error = ?err, path = %file_path.display(), "failed to persist rate limits");
            }
        }
        Err(err) => {
            tracing::debug!(error = ?err, path = %file_path.display(), "failed to serialize rate limits");
        }
    }
}

pub(crate) fn load_login_session_lines(
    config: &Config,
    active_rate_limits: &[RateLimitSnapshotDisplay],
    now: DateTime<Local>,
) -> Vec<String> {
    let config_toml = load_session_status_config(config.codex_home.join(CONFIG_TOML_FILE));
    let has_profile_named_default = config_toml
        .as_ref()
        .is_some_and(|toml| toml.profiles.contains_key("default"));
    let active_session_key = config
        .active_profile
        .clone()
        .map(LoginSessionKey::Profile)
        .unwrap_or(LoginSessionKey::Legacy);

    let mut sessions = BTreeMap::from([(
        LoginSessionKey::Legacy,
        config_toml
            .as_ref()
            .and_then(|toml| toml.model_provider.clone())
            .unwrap_or_else(|| "openai".to_string()),
    )]);
    if let Some(toml) = config_toml.as_ref() {
        for (profile, profile_config) in &toml.profiles {
            let provider_id = profile_config
                .model_provider
                .clone()
                .or_else(|| toml.model_provider.clone())
                .unwrap_or_else(|| "openai".to_string());
            sessions.insert(LoginSessionKey::Profile(profile.clone()), provider_id);
        }
    }
    sessions
        .entry(active_session_key.clone())
        .or_insert_with(|| config.model_provider_id.clone());

    let mut lines = Vec::new();
    for (session_key, provider_id) in sessions {
        let is_active = session_key == active_session_key;
        let auth_home = match &session_key {
            LoginSessionKey::Legacy => auth_storage_home(&config.codex_home, None),
            LoginSessionKey::Profile(profile) => {
                auth_storage_home(&config.codex_home, Some(profile))
            }
        };
        let auth = CodexAuth::from_auth_storage(&auth_home, config.cli_auth_credentials_store_mode)
            .ok()
            .flatten();
        let session_snapshots = if is_active && !active_rate_limits.is_empty() {
            active_rate_limits.to_vec()
        } else {
            load_persisted_rate_limits(&auth_home)
        };

        if !is_active && auth.is_none() && session_snapshots.is_empty() {
            continue;
        }

        let provider = if is_active {
            format_provider_summary(
                &config.model_provider_id,
                Some(config.model_provider.name.as_str()),
                config.model_provider.base_url.as_deref(),
            )
        } else {
            let provider_toml = config_toml
                .as_ref()
                .and_then(|toml| toml.model_providers.get(&provider_id));
            format_provider_summary(
                &provider_id,
                provider_toml.and_then(|provider| provider.name.as_deref()),
                provider_toml.and_then(|provider| provider.base_url.as_deref()),
            )
        };

        let summary = LoginSessionSummary {
            name: session_name_label(&session_key, has_profile_named_default),
            is_active,
            provider,
            account: auth
                .as_ref()
                .map(format_account_summary)
                .unwrap_or_else(|| "not logged in".to_string()),
            limits: format_limits_summary(&session_snapshots, now),
        };
        lines.push(format_login_session_summary(&summary));
    }

    lines
}

fn load_session_status_config(path: impl AsRef<Path>) -> Option<SessionStatusConfigToml> {
    let contents = fs::read_to_string(path).ok()?;
    toml::from_str(&contents).ok()
}

fn load_persisted_rate_limits(auth_home: &Path) -> Vec<RateLimitSnapshotDisplay> {
    let file_path = auth_home.join(RATE_LIMITS_FILE);
    let Some(stored) = load_stored_rate_limits_file(&file_path) else {
        return Vec::new();
    };

    stored
        .snapshots
        .into_values()
        .map(|stored| {
            let captured_at = stored.captured_at.with_timezone(&Local);
            let limit_name = stored
                .snapshot
                .limit_name
                .clone()
                .or_else(|| stored.snapshot.limit_id.clone())
                .unwrap_or_else(|| "codex".to_string());
            rate_limit_snapshot_display_for_limit(&stored.snapshot, limit_name, captured_at)
        })
        .collect()
}

fn load_stored_rate_limits_file(path: &Path) -> Option<StoredRateLimitSnapshots> {
    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn format_provider_summary(
    provider_id: &str,
    name: Option<&str>,
    base_url: Option<&str>,
) -> String {
    let provider_name = name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(provider_id);
    match sanitize_base_url(base_url) {
        Some(base_url) => format!("{provider_name} - {base_url}"),
        None => provider_name.to_string(),
    }
}

fn format_account_summary(auth: &CodexAuth) -> String {
    match auth.auth_mode() {
        AuthMode::ApiKey => "api key".to_string(),
        AuthMode::Chatgpt => {
            let email = auth.get_account_email();
            let plan = auth.account_plan_type().map(|plan_type| match plan_type {
                PlanType::Unknown => "Unknown".to_string(),
                other => format!("{other:?}"),
            });
            match (email, plan) {
                (Some(email), Some(plan)) => format!("{email} ({plan})"),
                (Some(email), None) => email,
                (None, Some(plan)) => plan,
                (None, None) => "ChatGPT".to_string(),
            }
        }
    }
}

fn format_limits_summary(snapshots: &[RateLimitSnapshotDisplay], now: DateTime<Local>) -> String {
    if snapshots.is_empty() {
        return "no limits yet".to_string();
    }

    match compose_rate_limit_data_many(snapshots, now) {
        StatusRateLimitData::Available(rows) => format_limit_rows(&rows),
        StatusRateLimitData::Stale(rows) => format!("{} (stale)", format_limit_rows(&rows)),
        StatusRateLimitData::Missing => "no limits yet".to_string(),
    }
}

fn format_limit_rows(rows: &[StatusRateLimitRow]) -> String {
    let parts: Vec<String> = rows.iter().filter_map(format_limit_row).collect();
    if parts.is_empty() {
        "no limits yet".to_string()
    } else {
        parts.join(", ")
    }
}

fn format_limit_row(row: &StatusRateLimitRow) -> Option<String> {
    match &row.value {
        StatusRateLimitValue::Window { percent_used, .. } => Some(format!(
            "{} {}",
            row.label,
            format_status_limit_summary((100.0 - percent_used).clamp(0.0, 100.0))
        )),
        StatusRateLimitValue::Text(text) if text.trim().is_empty() => Some(row.label.clone()),
        StatusRateLimitValue::Text(text) => Some(format!("{} {}", row.label, text.trim())),
    }
}

fn format_login_session_summary(session: &LoginSessionSummary) -> String {
    let current = if session.is_active { " (current)" } else { "" };
    format!(
        "{}{}: {} • {} • {}",
        session.name, current, session.provider, session.account, session.limits
    )
}

fn session_name_label(session_key: &LoginSessionKey, has_profile_named_default: bool) -> String {
    match session_key {
        LoginSessionKey::Legacy if has_profile_named_default => "default (legacy)".to_string(),
        LoginSessionKey::Legacy => "default".to_string(),
        LoginSessionKey::Profile(profile) => profile.clone(),
    }
}

fn sanitize_base_url(base_url: Option<&str>) -> Option<String> {
    let trimmed = base_url.map(str::trim).filter(|value| !value.is_empty())?;
    let without_trailing_slash = trimmed.trim_end_matches('/');
    Some(without_trailing_slash.to_string())
}
