use super::new_status_output;
use super::rate_limit_snapshot_display;
use crate::history_cell::HistoryCell;
use chrono::Duration as ChronoDuration;
use chrono::TimeZone;
use chrono::Utc;
use base64::Engine;
use codex_core::AuthManager;
use codex_core::auth::auth_storage_home;
use codex_core::config::Config;
use codex_core::config::ConfigBuilder;
use codex_protocol::ThreadId;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::CreditsSnapshot;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_protocol::protocol::RateLimitWindow;
use codex_protocol::protocol::SandboxPolicy;
use codex_protocol::protocol::TokenUsage;
use codex_protocol::protocol::TokenUsageInfo;
use insta::assert_snapshot;
use pretty_assertions::assert_eq;
use ratatui::prelude::*;
use serde_json::json;
use std::path::PathBuf;
use tempfile::TempDir;

async fn test_config(temp_home: &TempDir) -> Config {
    ConfigBuilder::default()
        .codex_home(temp_home.path().to_path_buf())
        .build()
        .await
        .expect("load config")
}

fn test_auth_manager(config: &Config) -> AuthManager {
    AuthManager::new(
        auth_storage_home(&config.codex_home, config.active_profile.as_deref()),
        false,
        config.cli_auth_credentials_store_mode,
    )
}

fn token_info_for(model_slug: &str, config: &Config, usage: &TokenUsage) -> TokenUsageInfo {
    let context_window =
        codex_core::test_support::construct_model_info_offline(model_slug, config).context_window;
    TokenUsageInfo {
        total_token_usage: usage.clone(),
        last_token_usage: usage.clone(),
        model_context_window: context_window,
    }
}

fn render_lines(lines: &[Line<'static>]) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect()
}

fn sanitize_directory(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| {
            if let (Some(dir_pos), Some(pipe_idx)) = (line.find("Directory: "), line.rfind('│')) {
                let prefix = &line[..dir_pos + "Directory: ".len()];
                let suffix = &line[pipe_idx..];
                let content_width = pipe_idx.saturating_sub(dir_pos + "Directory: ".len());
                let replacement = "[[workspace]]";
                let mut rebuilt = prefix.to_string();
                rebuilt.push_str(replacement);
                if content_width > replacement.len() {
                    rebuilt.push_str(&" ".repeat(content_width - replacement.len()));
                }
                rebuilt.push_str(suffix);
                rebuilt
            } else {
                line
            }
        })
        .collect()
}

fn reset_at_from(captured_at: &chrono::DateTime<chrono::Local>, seconds: i64) -> i64 {
    (*captured_at + ChronoDuration::seconds(seconds))
        .with_timezone(&Utc)
        .timestamp()
}

fn write_chatgpt_auth(home: &std::path::Path, email: &str, plan: &str) {
    #[derive(serde::Serialize)]
    struct Header {
        alg: &'static str,
        typ: &'static str,
    }

    let auth_payload = json!({
        "chatgpt_user_id": "user-12345",
        "user_id": "user-12345",
        "chatgpt_plan_type": plan,
    });
    let payload = json!({
        "email": email,
        "email_verified": true,
        "https://api.openai.com/auth": auth_payload,
    });
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let header = Header {
        alg: "none",
        typ: "JWT",
    };
    let header_b64 = encode(&serde_json::to_vec(&header).expect("header"));
    let payload_b64 = encode(&serde_json::to_vec(&payload).expect("payload"));
    let signature_b64 = encode(b"sig");
    let fake_jwt = format!("{header_b64}.{payload_b64}.{signature_b64}");

    std::fs::create_dir_all(home).expect("create auth dir");
    std::fs::write(
        home.join("auth.json"),
        serde_json::to_string_pretty(&json!({
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": fake_jwt,
                "access_token": "test-access-token",
                "refresh_token": "",
                "account_id": "workspace-123",
            },
            "last_refresh": "2025-01-01T00:00:00Z",
        }))
        .expect("serialize auth"),
    )
    .expect("write auth");
}

fn write_rate_limit_cache(
    home: &std::path::Path,
    captured_at: chrono::DateTime<chrono::Local>,
    limit_id: &str,
    used_percent: f64,
) {
    std::fs::create_dir_all(home).expect("create rate limit dir");
    std::fs::write(
        home.join("rate_limits.json"),
        serde_json::to_string_pretty(&json!({
            "snapshots": {
                limit_id: {
                    "captured_at": captured_at.with_timezone(&Utc).to_rfc3339(),
                    "snapshot": {
                        "limit_id": limit_id,
                        "limit_name": limit_id,
                        "primary": {
                            "used_percent": used_percent,
                            "window_minutes": 300,
                            "resets_at": reset_at_from(&captured_at, 1800),
                        },
                        "secondary": serde_json::Value::Null,
                        "credits": serde_json::Value::Null,
                        "plan_type": serde_json::Value::Null,
                    }
                }
            }
        }))
        .expect("serialize rate limits"),
    )
    .expect("write rate limits");
}

#[tokio::test]
async fn status_snapshot_includes_reasoning_details() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.model_provider_id = "openai".to_string();
    config.model_reasoning_summary = Some(ReasoningSummary::Detailed);
    config
        .permissions
        .sandbox_policy
        .set(SandboxPolicy::WorkspaceWrite {
            writable_roots: Vec::new(),
            read_only_access: Default::default(),
            network_access: false,
            exclude_tmpdir_env_var: false,
            exclude_slash_tmp: false,
        })
        .expect("set sandbox policy");

    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 1_200,
        cached_input_tokens: 200,
        output_tokens: 900,
        reasoning_output_tokens: 150,
        total_tokens: 2_250,
    };

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 1, 2, 3, 4, 5)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 72.5,
            window_minutes: Some(300),
            resets_at: Some(reset_at_from(&captured_at, 600)),
        }),
        secondary: Some(RateLimitWindow {
            used_percent: 45.0,
            window_minutes: Some(10080),
            resets_at: Some(reset_at_from(&captured_at, 1_200)),
        }),
        credits: None,
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);

    let reasoning_effort_override = Some(Some(ReasoningEffort::High));
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        reasoning_effort_override,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_lists_login_sessions() {
    let temp_home = TempDir::new().expect("temp home");
    std::fs::write(
        temp_home.path().join("config.toml"),
        r#"
model = "gpt-5.1-codex"
model_provider = "openai"
profile = "work"

[profiles.work]
model_provider = "openai"

[profiles.backup]
model_provider = "backup"

[model_providers.backup]
name = "Backup"
base_url = "https://backup.example/v1"
requires_openai_auth = true
"#,
    )
    .expect("write config");

    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex".to_string());
    config.cwd = PathBuf::from("/workspace/tests");

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 2, 3, 4, 5, 6)
        .single()
        .expect("timestamp");
    let work_home = auth_storage_home(&config.codex_home, Some("work"));
    let backup_home = auth_storage_home(&config.codex_home, Some("backup"));
    write_chatgpt_auth(&work_home, "work@example.com", "pro");
    write_chatgpt_auth(&backup_home, "backup@example.com", "plus");
    write_rate_limit_cache(&backup_home, captured_at, "codex", 62.0);

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 900,
        cached_input_tokens: 100,
        output_tokens: 500,
        reasoning_output_tokens: 0,
        total_tokens: 1_500,
    };
    let snapshot = RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: Some("codex".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 28.0,
            window_minutes: Some(300),
            resets_at: Some(reset_at_from(&captured_at, 900)),
        }),
        secondary: None,
        credits: None,
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);
    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);

    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let rendered_lines = render_lines(&composite.display_lines(120));
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_permissions_non_default_workspace_write_is_custom() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.model_provider_id = "openai".to_string();
    config
        .permissions
        .approval_policy
        .set(AskForApproval::OnRequest)
        .expect("set approval policy");
    config
        .permissions
        .sandbox_policy
        .set(SandboxPolicy::WorkspaceWrite {
            writable_roots: Vec::new(),
            read_only_access: Default::default(),
            network_access: true,
            exclude_tmpdir_env_var: false,
            exclude_slash_tmp: false,
        })
        .expect("set sandbox policy");
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage::default();
    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 1, 2, 3, 4, 5)
        .single()
        .expect("timestamp");
    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());

    let composite = new_status_output(
        &config,
        &auth_manager,
        None,
        &usage,
        &None,
        None,
        None,
        None,
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let rendered_lines = render_lines(&composite.display_lines(80));
    let permissions_line = rendered_lines
        .iter()
        .find(|line| line.contains("Permissions:"))
        .expect("permissions line");
    let permissions_text = permissions_line
        .split("Permissions:")
        .nth(1)
        .map(str::trim)
        .map(|text| text.trim_end_matches('│'))
        .map(str::trim);

    assert_eq!(
        permissions_text,
        Some("Custom (workspace-write with network access, on-request)")
    );
}

#[tokio::test]
async fn status_snapshot_includes_forked_from() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.model_provider_id = "openai".to_string();
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 800,
        cached_input_tokens: 0,
        output_tokens: 400,
        reasoning_output_tokens: 0,
        total_tokens: 1_200,
    };

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 8, 9, 10, 11, 12)
        .single()
        .expect("valid time");

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let session_id =
        ThreadId::from_string("0f0f3c13-6cf9-4aa4-8b80-7d49c2f1be2e").expect("session id");
    let forked_from =
        ThreadId::from_string("e9f18a88-8081-4e51-9d4e-8af5cde2d8dd").expect("forked id");

    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &Some(session_id),
        None,
        Some(forked_from),
        None,
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_includes_monthly_limit() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.model_provider_id = "openai".to_string();
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 800,
        cached_input_tokens: 0,
        output_tokens: 400,
        reasoning_output_tokens: 0,
        total_tokens: 1_200,
    };

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 5, 6, 7, 8, 9)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 12.0,
            window_minutes: Some(43_200),
            resets_at: Some(reset_at_from(&captured_at, 86_400)),
        }),
        secondary: None,
        credits: None,
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_shows_unlimited_credits() {
    let temp_home = TempDir::new().expect("temp home");
    let config = test_config(&temp_home).await;
    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage::default();
    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 2, 3, 4, 5, 6)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: None,
        secondary: None,
        credits: Some(CreditsSnapshot {
            has_credits: true,
            unlimited: true,
            balance: None,
        }),
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);
    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let rendered = render_lines(&composite.display_lines(120));
    assert!(
        rendered
            .iter()
            .any(|line| line.contains("Credits:") && line.contains("Unlimited")),
        "expected Credits: Unlimited line, got {rendered:?}"
    );
}

#[tokio::test]
async fn status_snapshot_shows_positive_credits() {
    let temp_home = TempDir::new().expect("temp home");
    let config = test_config(&temp_home).await;
    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage::default();
    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 3, 4, 5, 6, 7)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: None,
        secondary: None,
        credits: Some(CreditsSnapshot {
            has_credits: true,
            unlimited: false,
            balance: Some("12.5".to_string()),
        }),
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);
    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let rendered = render_lines(&composite.display_lines(120));
    assert!(
        rendered
            .iter()
            .any(|line| line.contains("Credits:") && line.contains("13 credits")),
        "expected Credits line with rounded credits, got {rendered:?}"
    );
}

#[tokio::test]
async fn status_snapshot_hides_zero_credits() {
    let temp_home = TempDir::new().expect("temp home");
    let config = test_config(&temp_home).await;
    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage::default();
    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 4, 5, 6, 7, 8)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: None,
        secondary: None,
        credits: Some(CreditsSnapshot {
            has_credits: true,
            unlimited: false,
            balance: Some("0".to_string()),
        }),
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);
    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let rendered = render_lines(&composite.display_lines(120));
    assert!(
        rendered.iter().all(|line| !line.contains("Credits:")),
        "expected no Credits line, got {rendered:?}"
    );
}

#[tokio::test]
async fn status_snapshot_hides_when_has_no_credits_flag() {
    let temp_home = TempDir::new().expect("temp home");
    let config = test_config(&temp_home).await;
    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage::default();
    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 5, 6, 7, 8, 9)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: None,
        secondary: None,
        credits: Some(CreditsSnapshot {
            has_credits: false,
            unlimited: true,
            balance: None,
        }),
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);
    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let rendered = render_lines(&composite.display_lines(120));
    assert!(
        rendered.iter().all(|line| !line.contains("Credits:")),
        "expected no Credits line when has_credits is false, got {rendered:?}"
    );
}

#[tokio::test]
async fn status_card_token_usage_excludes_cached_tokens() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 1_200,
        cached_input_tokens: 200,
        output_tokens: 900,
        reasoning_output_tokens: 0,
        total_tokens: 2_100,
    };

    let now = chrono::Local
        .with_ymd_and_hms(2024, 1, 1, 0, 0, 0)
        .single()
        .expect("timestamp");

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        None,
        None,
        now,
        &model_slug,
        None,
        None,
    );
    let rendered = render_lines(&composite.display_lines(120));

    assert!(
        rendered.iter().all(|line| !line.contains("cached")),
        "cached tokens should not be displayed, got: {rendered:?}"
    );
}

#[tokio::test]
async fn status_snapshot_truncates_in_narrow_terminal() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.model_provider_id = "openai".to_string();
    config.model_reasoning_summary = Some(ReasoningSummary::Detailed);
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 1_200,
        cached_input_tokens: 200,
        output_tokens: 900,
        reasoning_output_tokens: 150,
        total_tokens: 2_250,
    };

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 1, 2, 3, 4, 5)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 72.5,
            window_minutes: Some(300),
            resets_at: Some(reset_at_from(&captured_at, 600)),
        }),
        secondary: None,
        credits: None,
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let reasoning_effort_override = Some(Some(ReasoningEffort::High));
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        reasoning_effort_override,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(70));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");

    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_shows_missing_limits_message() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 500,
        cached_input_tokens: 0,
        output_tokens: 250,
        reasoning_output_tokens: 0,
        total_tokens: 750,
    };

    let now = chrono::Local
        .with_ymd_and_hms(2024, 2, 3, 4, 5, 6)
        .single()
        .expect("timestamp");

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        None,
        None,
        now,
        &model_slug,
        None,
        None,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_includes_credits_and_limits() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex".to_string());
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 1_500,
        cached_input_tokens: 100,
        output_tokens: 600,
        reasoning_output_tokens: 0,
        total_tokens: 2_200,
    };

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 7, 8, 9, 10, 11)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 45.0,
            window_minutes: Some(300),
            resets_at: Some(reset_at_from(&captured_at, 900)),
        }),
        secondary: Some(RateLimitWindow {
            used_percent: 30.0,
            window_minutes: Some(10_080),
            resets_at: Some(reset_at_from(&captured_at, 2_700)),
        }),
        credits: Some(CreditsSnapshot {
            has_credits: true,
            unlimited: false,
            balance: Some("37.5".to_string()),
        }),
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_shows_empty_limits_message() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 500,
        cached_input_tokens: 0,
        output_tokens: 250,
        reasoning_output_tokens: 0,
        total_tokens: 750,
    };

    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: None,
        secondary: None,
        credits: None,
        plan_type: None,
    };
    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 6, 7, 8, 9, 10)
        .single()
        .expect("timestamp");
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        captured_at,
        &model_slug,
        None,
        None,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_shows_stale_limits_message() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex-max".to_string());
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 1_200,
        cached_input_tokens: 200,
        output_tokens: 900,
        reasoning_output_tokens: 150,
        total_tokens: 2_250,
    };

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 1, 2, 3, 4, 5)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 72.5,
            window_minutes: Some(300),
            resets_at: Some(reset_at_from(&captured_at, 600)),
        }),
        secondary: Some(RateLimitWindow {
            used_percent: 40.0,
            window_minutes: Some(10_080),
            resets_at: Some(reset_at_from(&captured_at, 1_800)),
        }),
        credits: None,
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);
    let now = captured_at + ChronoDuration::minutes(20);

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        now,
        &model_slug,
        None,
        None,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_snapshot_cached_limits_hide_credits_without_flag() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model = Some("gpt-5.1-codex".to_string());
    config.cwd = PathBuf::from("/workspace/tests");

    let auth_manager = test_auth_manager(&config);
    let usage = TokenUsage {
        input_tokens: 900,
        cached_input_tokens: 200,
        output_tokens: 350,
        reasoning_output_tokens: 0,
        total_tokens: 1_450,
    };

    let captured_at = chrono::Local
        .with_ymd_and_hms(2024, 9, 10, 11, 12, 13)
        .single()
        .expect("timestamp");
    let snapshot = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 60.0,
            window_minutes: Some(300),
            resets_at: Some(reset_at_from(&captured_at, 1_200)),
        }),
        secondary: Some(RateLimitWindow {
            used_percent: 35.0,
            window_minutes: Some(10_080),
            resets_at: Some(reset_at_from(&captured_at, 2_400)),
        }),
        credits: Some(CreditsSnapshot {
            has_credits: false,
            unlimited: false,
            balance: Some("80".to_string()),
        }),
        plan_type: None,
    };
    let rate_display = rate_limit_snapshot_display(&snapshot, captured_at);
    let now = captured_at + ChronoDuration::minutes(20);

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = token_info_for(&model_slug, &config, &usage);
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &usage,
        &None,
        None,
        None,
        Some(&rate_display),
        None,
        now,
        &model_slug,
        None,
        None,
    );
    let mut rendered_lines = render_lines(&composite.display_lines(80));
    if cfg!(windows) {
        for line in &mut rendered_lines {
            *line = line.replace('\\', "/");
        }
    }
    let sanitized = sanitize_directory(rendered_lines).join("\n");
    assert_snapshot!(sanitized);
}

#[tokio::test]
async fn status_context_window_uses_last_usage() {
    let temp_home = TempDir::new().expect("temp home");
    let mut config = test_config(&temp_home).await;
    config.model_context_window = Some(272_000);

    let auth_manager = test_auth_manager(&config);
    let total_usage = TokenUsage {
        input_tokens: 12_800,
        cached_input_tokens: 0,
        output_tokens: 879,
        reasoning_output_tokens: 0,
        total_tokens: 102_000,
    };
    let last_usage = TokenUsage {
        input_tokens: 12_800,
        cached_input_tokens: 0,
        output_tokens: 879,
        reasoning_output_tokens: 0,
        total_tokens: 13_679,
    };

    let now = chrono::Local
        .with_ymd_and_hms(2024, 6, 1, 12, 0, 0)
        .single()
        .expect("timestamp");

    let model_slug = codex_core::test_support::get_model_offline(config.model.as_deref());
    let token_info = TokenUsageInfo {
        total_token_usage: total_usage.clone(),
        last_token_usage: last_usage,
        model_context_window: config.model_context_window,
    };
    let composite = new_status_output(
        &config,
        &auth_manager,
        Some(&token_info),
        &total_usage,
        &None,
        None,
        None,
        None,
        None,
        now,
        &model_slug,
        None,
        None,
    );
    let rendered_lines = render_lines(&composite.display_lines(80));
    let context_line = rendered_lines
        .into_iter()
        .find(|line| line.contains("Context window"))
        .expect("context line");

    assert!(
        context_line.contains("13.7K used / 272K"),
        "expected context line to reflect last usage tokens, got: {context_line}"
    );
    assert!(
        !context_line.contains("102K"),
        "context line should not use total aggregated tokens, got: {context_line}"
    );
}
