use crate::app_backtrack::BacktrackState;
use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use crate::backtrack_helpers;
use crate::bottom_pane::SelectionAction;
use crate::bottom_pane::SelectionItem;
use crate::chatwidget::ChatWidget;
use crate::file_search::FileSearchManager;
use crate::pager_overlay::Overlay;
use crate::resume_picker::ResumeSelection;
use crate::tui;
use crate::tui::TuiEvent;
use chrono::Utc;
use codex_ansi_escape::ansi_escape_line;
use codex_core::AuthManager;
use codex_core::ConversationManager;
use codex_core::config::Config;
use codex_core::config::persist_model_selection;
use codex_core::model_family::find_family_for_model;
use codex_core::protocol::Op;
use codex_core::protocol::TokenUsage;
use codex_core::protocol_config_types::ReasoningEffort as ReasoningEffortConfig;
use codex_protocol::mcp_protocol::ConversationId;
use color_eyre::eyre::Result;
use color_eyre::eyre::WrapErr;
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use crossterm::terminal::supports_keyboard_enhancement;
use ratatui::style::Stylize;
use ratatui::text::Line;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use tokio::select;
use tokio::sync::mpsc::unbounded_channel;
// use uuid::Uuid;

pub(crate) struct App {
    pub(crate) server: Arc<ConversationManager>,
    pub(crate) app_event_tx: AppEventSender,
    pub(crate) chat_widget: ChatWidget,
    pub(crate) auth_manager: Arc<AuthManager>,

    /// Config is stored here so we can recreate ChatWidgets as needed.
    pub(crate) config: Config,
    pub(crate) active_profile: Option<String>,

    pub(crate) file_search: FileSearchManager,

    pub(crate) transcript_lines: Vec<Line<'static>>,

    // Pager overlay state (Transcript or Static like Diff)
    pub(crate) overlay: Option<Overlay>,
    pub(crate) deferred_history_lines: Vec<Line<'static>>,
    has_emitted_history_lines: bool,

    pub(crate) enhanced_keys_supported: bool,

    /// Controls the animation thread that sends CommitTick events.
    pub(crate) commit_anim_running: Arc<AtomicBool>,

    // Esc-backtracking state grouped
    pub(crate) backtrack: crate::app_backtrack::BacktrackState,

    pending_history_request: Option<HistoryRequest>,
    queued_auto_checkpoint: Option<AutoCheckpointRequest>,
}

impl App {
    pub async fn run(
        tui: &mut tui::Tui,
        auth_manager: Arc<AuthManager>,
        config: Config,
        active_profile: Option<String>,
        initial_prompt: Option<String>,
        initial_images: Vec<PathBuf>,
        resume_selection: ResumeSelection,
    ) -> Result<TokenUsage> {
        use tokio_stream::StreamExt;
        let (app_event_tx, mut app_event_rx) = unbounded_channel();
        let app_event_tx = AppEventSender::new(app_event_tx);

        let conversation_manager = Arc::new(ConversationManager::new(auth_manager.clone()));

        let enhanced_keys_supported = supports_keyboard_enhancement().unwrap_or(false);

        let chat_widget = match resume_selection {
            ResumeSelection::StartFresh | ResumeSelection::Exit => {
                let init = crate::chatwidget::ChatWidgetInit {
                    config: config.clone(),
                    frame_requester: tui.frame_requester(),
                    app_event_tx: app_event_tx.clone(),
                    initial_prompt: initial_prompt.clone(),
                    initial_images: initial_images.clone(),
                    enhanced_keys_supported,
                    auth_manager: auth_manager.clone(),
                };
                ChatWidget::new(init, conversation_manager.clone())
            }
            ResumeSelection::Resume(path) => {
                let resumed = conversation_manager
                    .resume_conversation_from_rollout(
                        config.clone(),
                        path.clone(),
                        auth_manager.clone(),
                    )
                    .await
                    .wrap_err_with(|| {
                        format!("Failed to resume session from {}", path.display())
                    })?;
                let init = crate::chatwidget::ChatWidgetInit {
                    config: config.clone(),
                    frame_requester: tui.frame_requester(),
                    app_event_tx: app_event_tx.clone(),
                    initial_prompt: initial_prompt.clone(),
                    initial_images: initial_images.clone(),
                    enhanced_keys_supported,
                    auth_manager: auth_manager.clone(),
                };
                ChatWidget::new_from_existing(
                    init,
                    resumed.conversation,
                    resumed.session_configured,
                )
            }
        };

        let file_search = FileSearchManager::new(config.cwd.clone(), app_event_tx.clone());

        let mut app = Self {
            server: conversation_manager,
            app_event_tx,
            chat_widget,
            auth_manager: auth_manager.clone(),
            config,
            active_profile,
            file_search,
            enhanced_keys_supported,
            transcript_lines: Vec::new(),
            overlay: None,
            deferred_history_lines: Vec::new(),
            has_emitted_history_lines: false,
            commit_anim_running: Arc::new(AtomicBool::new(false)),
            backtrack: BacktrackState::default(),
            pending_history_request: None,
            queued_auto_checkpoint: None,
        };

        let tui_events = tui.event_stream();
        tokio::pin!(tui_events);

        tui.frame_requester().schedule_frame();

        while select! {
            Some(event) = app_event_rx.recv() => {
                app.handle_event(tui, event).await?
            }
            Some(event) = tui_events.next() => {
                app.handle_tui_event(tui, event).await?
            }
        } {}
        tui.terminal.clear()?;
        Ok(app.token_usage())
    }

    pub(crate) async fn handle_tui_event(
        &mut self,
        tui: &mut tui::Tui,
        event: TuiEvent,
    ) -> Result<bool> {
        if self.overlay.is_some() {
            let _ = self.handle_backtrack_overlay_event(tui, event).await?;
        } else {
            match event {
                TuiEvent::Key(key_event) => {
                    self.handle_key_event(tui, key_event).await;
                }
                TuiEvent::Paste(pasted) => {
                    // Many terminals convert newlines to \r when pasting (e.g., iTerm2),
                    // but tui-textarea expects \n. Normalize CR to LF.
                    // [tui-textarea]: https://github.com/rhysd/tui-textarea/blob/4d18622eeac13b309e0ff6a55a46ac6706da68cf/src/textarea.rs#L782-L783
                    // [iTerm2]: https://github.com/gnachman/iTerm2/blob/5d0c0d9f68523cbd0494dad5422998964a2ecd8d/sources/iTermPasteHelper.m#L206-L216
                    let pasted = pasted.replace("\r", "\n");
                    self.chat_widget.handle_paste(pasted);
                }
                TuiEvent::Draw => {
                    self.chat_widget.maybe_post_pending_notification(tui);
                    if self
                        .chat_widget
                        .handle_paste_burst_tick(tui.frame_requester())
                    {
                        return Ok(true);
                    }
                    tui.draw(
                        self.chat_widget.desired_height(tui.terminal.size()?.width),
                        |frame| {
                            frame.render_widget_ref(&self.chat_widget, frame.area());
                            if let Some((x, y)) = self.chat_widget.cursor_pos(frame.area()) {
                                frame.set_cursor_position((x, y));
                            }
                        },
                    )?;
                }
            }
        }
        Ok(true)
    }

    async fn handle_event(&mut self, tui: &mut tui::Tui, event: AppEvent) -> Result<bool> {
        match event {
            AppEvent::NewSession => {
                let init = crate::chatwidget::ChatWidgetInit {
                    config: self.config.clone(),
                    frame_requester: tui.frame_requester(),
                    app_event_tx: self.app_event_tx.clone(),
                    initial_prompt: None,
                    initial_images: Vec::new(),
                    enhanced_keys_supported: self.enhanced_keys_supported,
                    auth_manager: self.auth_manager.clone(),
                };
                self.chat_widget = ChatWidget::new(init, self.server.clone());
                self.clear_auto_checkpoint_queue();
                tui.frame_requester().schedule_frame();
            }
            AppEvent::InsertHistoryCell(cell) => {
                let mut cell_transcript = cell.transcript_lines();
                if !cell.is_stream_continuation() && !self.transcript_lines.is_empty() {
                    cell_transcript.insert(0, Line::from(""));
                }
                if let Some(Overlay::Transcript(t)) = &mut self.overlay {
                    t.insert_lines(cell_transcript.clone());
                    tui.frame_requester().schedule_frame();
                }
                self.transcript_lines.extend(cell_transcript.clone());
                let mut display = cell.display_lines(tui.terminal.last_known_screen_size.width);
                if !display.is_empty() {
                    // Only insert a separating blank line for new cells that are not
                    // part of an ongoing stream. Streaming continuations should not
                    // accrue extra blank lines between chunks.
                    if !cell.is_stream_continuation() {
                        if self.has_emitted_history_lines {
                            display.insert(0, Line::from(""));
                        } else {
                            self.has_emitted_history_lines = true;
                        }
                    }
                    if self.overlay.is_some() {
                        self.deferred_history_lines.extend(display);
                    } else {
                        tui.insert_history_lines(display);
                    }
                }
            }
            AppEvent::StartCommitAnimation => {
                if self
                    .commit_anim_running
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    let tx = self.app_event_tx.clone();
                    let running = self.commit_anim_running.clone();
                    thread::spawn(move || {
                        while running.load(Ordering::Relaxed) {
                            thread::sleep(Duration::from_millis(50));
                            tx.send(AppEvent::CommitTick);
                        }
                    });
                }
            }
            AppEvent::StopCommitAnimation => {
                self.commit_anim_running.store(false, Ordering::Release);
            }
            AppEvent::CommitTick => {
                self.chat_widget.on_commit_tick();
            }
            AppEvent::CodexEvent(event) => {
                self.chat_widget.handle_codex_event(event);
            }
            AppEvent::ConversationHistory(ev) => {
                if self.try_handle_pending_history_request(tui, &ev).await? {
                    return Ok(true);
                }
                self.on_conversation_history_for_backtrack(tui, ev).await?;
            }
            AppEvent::ExitRequest => {
                return Ok(false);
            }
            AppEvent::PopLastTurn => {
                self.handle_pop_last_turn().await?;
            }
            AppEvent::RetryLastTurn => {
                self.handle_retry_last_turn().await?;
            }
            AppEvent::ExportTranscript => {
                self.export_transcript().await?;
            }
            AppEvent::SaveCheckpoint => {
                self.handle_save_checkpoint().await?;
            }
            AppEvent::TriggerAutoCheckpoint => {
                self.queue_auto_checkpoint();
            }
            AppEvent::OpenLoadSaves => {
                self.open_load_saves_popup().await?;
            }
            AppEvent::LoadSavedConversation { path } => {
                self.load_saved_conversation(tui, path).await?;
            }
            AppEvent::CodexOp(op) => self.chat_widget.submit_op(op),
            AppEvent::DiffResult(text) => {
                // Clear the in-progress state in the bottom pane
                self.chat_widget.on_diff_complete();
                // Enter alternate screen using TUI helper and build pager lines
                let _ = tui.enter_alt_screen();
                let pager_lines: Vec<ratatui::text::Line<'static>> = if text.trim().is_empty() {
                    vec!["No changes detected.".italic().into()]
                } else {
                    text.lines().map(ansi_escape_line).collect()
                };
                self.overlay = Some(Overlay::new_static_with_title(
                    pager_lines,
                    "D I F F".to_string(),
                ));
                tui.frame_requester().schedule_frame();
            }
            AppEvent::StartFileSearch(query) => {
                if !query.is_empty() {
                    self.file_search.on_user_query(query);
                }
            }
            AppEvent::FileSearchResult { query, matches } => {
                self.chat_widget.apply_file_search_result(query, matches);
            }
            AppEvent::UpdateReasoningEffort(effort) => {
                self.on_update_reasoning_effort(effort);
            }
            AppEvent::UpdateModel(model) => {
                self.chat_widget.set_model(&model);
                self.config.model = model.clone();
                if let Some(family) = find_family_for_model(&model) {
                    self.config.model_family = family;
                }
            }
            AppEvent::PersistModelSelection { model, effort } => {
                let profile = self.active_profile.as_deref();
                match persist_model_selection(&self.config.codex_home, profile, &model, effort)
                    .await
                {
                    Ok(()) => {
                        if let Some(profile) = profile {
                            self.chat_widget.add_info_message(
                                format!("Model changed to {model} for {profile} profile"),
                                None,
                            );
                        } else {
                            self.chat_widget
                                .add_info_message(format!("Model changed to {model}"), None);
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            error = %err,
                            "failed to persist model selection"
                        );
                        if let Some(profile) = profile {
                            self.chat_widget.add_error_message(format!(
                                "Failed to save model for profile `{profile}`: {err}"
                            ));
                        } else {
                            self.chat_widget
                                .add_error_message(format!("Failed to save default model: {err}"));
                        }
                    }
                }
            }
            AppEvent::UpdateAskForApprovalPolicy(policy) => {
                self.chat_widget.set_approval_policy(policy);
            }
            AppEvent::UpdateSandboxPolicy(policy) => {
                self.chat_widget.set_sandbox_policy(policy);
            }
        }
        Ok(true)
    }

    pub(crate) fn token_usage(&self) -> codex_core::protocol::TokenUsage {
        self.chat_widget.token_usage()
    }

    fn on_update_reasoning_effort(&mut self, effort: Option<ReasoningEffortConfig>) {
        self.chat_widget.set_reasoning_effort(effort);
        self.config.model_reasoning_effort = effort;
    }

    async fn handle_key_event(&mut self, tui: &mut tui::Tui, key_event: KeyEvent) {
        match key_event {
            KeyEvent {
                code: KeyCode::Char('t'),
                modifiers: crossterm::event::KeyModifiers::CONTROL,
                kind: KeyEventKind::Press,
                ..
            } => {
                // Enter alternate screen and set viewport to full size.
                let _ = tui.enter_alt_screen();
                self.overlay = Some(Overlay::new_transcript(self.transcript_lines.clone()));
                tui.frame_requester().schedule_frame();
            }
            // Esc primes/advances backtracking only in normal (not working) mode
            // with an empty composer. In any other state, forward Esc so the
            // active UI (e.g. status indicator, modals, popups) handles it.
            KeyEvent {
                code: KeyCode::Esc,
                kind: KeyEventKind::Press | KeyEventKind::Repeat,
                ..
            } => {
                if self.chat_widget.is_normal_backtrack_mode()
                    && self.chat_widget.composer_is_empty()
                {
                    self.handle_backtrack_esc_key(tui);
                } else {
                    self.chat_widget.handle_key_event(key_event);
                }
            }
            // Enter confirms backtrack when primed + count > 0. Otherwise pass to widget.
            KeyEvent {
                code: KeyCode::Enter,
                kind: KeyEventKind::Press,
                ..
            } if self.backtrack.primed
                && self.backtrack.count > 0
                && self.chat_widget.composer_is_empty() =>
            {
                // Delegate to helper for clarity; preserves behavior.
                self.confirm_backtrack_from_main();
            }
            KeyEvent {
                kind: KeyEventKind::Press | KeyEventKind::Repeat,
                ..
            } => {
                // Any non-Esc key press should cancel a primed backtrack.
                // This avoids stale "Esc-primed" state after the user starts typing
                // (even if they later backspace to empty).
                if key_event.code != KeyCode::Esc && self.backtrack.primed {
                    self.reset_backtrack_state();
                }
                self.chat_widget.handle_key_event(key_event);
            }
            _ => {
                // Ignore Release key events.
            }
        };
    }

    async fn handle_pop_last_turn(&mut self) -> Result<()> {
        if self.pending_history_request.is_some() {
            self.chat_widget
                .add_error_message("Another history operation is already in progress.".to_string());
            return Ok(());
        }

        let Some(conversation_id) = self.chat_widget.conversation_id() else {
            self.chat_widget
                .add_error_message("No active conversation to pop.".to_string());
            return Ok(());
        };

        if backtrack_helpers::find_nth_last_user_header_index(&self.transcript_lines, 1).is_none() {
            self.chat_widget
                .add_info_message("No user turns to remove.".to_string(), None);
            return Ok(());
        }

        self.pending_history_request = Some(HistoryRequest::Pop {
            conversation_id,
            drop_count: 1,
        });
        self.chat_widget.submit_op(Op::GetPath);
        Ok(())
    }

    async fn handle_retry_last_turn(&mut self) -> Result<()> {
        if self.pending_history_request.is_some() {
            self.chat_widget
                .add_error_message("Another history operation is already in progress.".to_string());
            return Ok(());
        }

        let Some(conversation_id) = self.chat_widget.conversation_id() else {
            self.chat_widget
                .add_error_message("No active conversation to retry.".to_string());
            return Ok(());
        };

        let Some(message) = backtrack_helpers::nth_last_user_text(&self.transcript_lines, 1) else {
            self.chat_widget
                .add_info_message("No previous user message to retry.".to_string(), None);
            return Ok(());
        };

        if message.trim().is_empty() {
            self.chat_widget
                .add_info_message("Latest user message is empty.".to_string(), None);
            return Ok(());
        }

        self.pending_history_request = Some(HistoryRequest::Retry {
            conversation_id,
            drop_count: 1,
            message,
        });
        self.chat_widget.submit_op(Op::GetPath);
        Ok(())
    }

    async fn handle_save_checkpoint(&mut self) -> Result<()> {
        if self.pending_history_request.is_some() {
            self.chat_widget
                .add_error_message("Another history operation is already in progress.".to_string());
            return Ok(());
        }

        let Some(conversation_id) = self.chat_widget.conversation_id() else {
            self.chat_widget
                .add_error_message("No active conversation to save.".to_string());
            return Ok(());
        };

        let target = self.generate_save_path(&conversation_id);
        if let Some(parent) = target.parent()
            && let Err(err) = tokio::fs::create_dir_all(parent).await
        {
            self.chat_widget.add_error_message(format!(
                "Failed to create save directory {}: {err}",
                parent.display()
            ));
            return Ok(());
        }

        self.pending_history_request = Some(HistoryRequest::Save {
            conversation_id,
            target,
        });
        self.chat_widget.submit_op(Op::GetPath);
        Ok(())
    }

    fn queue_auto_checkpoint(&mut self) {
        if self.config.auto_checkpoint_keep == 0 {
            return;
        }

        let Some(conversation_id) = self.chat_widget.conversation_id() else {
            return;
        };

        let target = self.generate_auto_save_path(&conversation_id);
        self.queued_auto_checkpoint = Some(AutoCheckpointRequest {
            conversation_id,
            target,
        });
        self.try_start_auto_checkpoint();
    }

    fn try_start_auto_checkpoint(&mut self) {
        if self.pending_history_request.is_some() {
            return;
        }
        if let Some(request) = self.queued_auto_checkpoint.take() {
            self.pending_history_request = Some(HistoryRequest::AutoSave {
                conversation_id: request.conversation_id,
                target: request.target,
            });
            self.chat_widget.submit_op(Op::GetPath);
        }
    }

    pub(crate) fn clear_auto_checkpoint_queue(&mut self) {
        self.queued_auto_checkpoint = None;
    }

    async fn export_transcript(&mut self) -> Result<()> {
        let now = Utc::now();
        let filename = format!(
            "codex-export-{}{:03}.md",
            now.format("%Y%m%d-%H%M%S"),
            now.timestamp_subsec_millis()
        );
        let mut path = std::env::temp_dir();
        path.push(filename);

        let mut content = String::new();
        content.push_str("# Codex Transcript Export\n\n");
        content.push_str(&format!("_Generated {}_\n\n", now.to_rfc3339()));
        for line in self.collect_transcript_lines() {
            content.push_str(&line);
            content.push('\n');
        }

        match tokio::fs::write(&path, content).await {
            Ok(_) => {
                self.chat_widget
                    .add_info_message(format!("Exported transcript to {}", path.display()), None);
            }
            Err(err) => {
                self.chat_widget.add_error_message(format!(
                    "Failed to export transcript to {}: {err}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    async fn open_load_saves_popup(&mut self) -> Result<()> {
        let saves = match self.list_saved_checkpoints().await {
            Ok(saves) => saves,
            Err(err) => {
                self.chat_widget
                    .add_error_message(format!("Failed to list saved checkpoints: {err}"));
                return Ok(());
            }
        };
        if saves.is_empty() {
            self.chat_widget
                .add_info_message("No saved checkpoints found.".to_string(), None);
            return Ok(());
        }

        let items: Vec<SelectionItem> = saves
            .into_iter()
            .map(|entry| {
                let SaveEntry {
                    path,
                    display,
                    description,
                    kind,
                    ..
                } = entry;
                let path_for_action = path;
                let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                    tx.send(AppEvent::LoadSavedConversation {
                        path: path_for_action.clone(),
                    });
                })];
                let mut name = display;
                if kind == SaveEntryKind::Auto {
                    name = format!("[Auto] {name}");
                }
                SelectionItem {
                    name,
                    description,
                    is_current: false,
                    actions,
                }
            })
            .collect();

        self.chat_widget.open_saved_sessions_popup(
            "Load saved session".to_string(),
            Some("Select a checkpoint to resume.".to_string()),
            Some("Press Enter to load or Esc to cancel".to_string()),
            items,
        );
        Ok(())
    }

    async fn load_saved_conversation(&mut self, tui: &mut tui::Tui, path: PathBuf) -> Result<()> {
        if let Err(err) = tokio::fs::metadata(&path).await {
            self.chat_widget.add_error_message(format!(
                "Saved checkpoint {} is not accessible: {err}",
                path.display()
            ));
            return Ok(());
        }

        let resumed = match self
            .server
            .resume_conversation_from_rollout(
                self.config.clone(),
                path.clone(),
                self.auth_manager.clone(),
            )
            .await
        {
            Ok(resumed) => resumed,
            Err(err) => {
                self.chat_widget
                    .add_error_message(format!("Failed to load checkpoint: {err}"));
                return Ok(());
            }
        };

        let init = crate::chatwidget::ChatWidgetInit {
            config: self.config.clone(),
            frame_requester: tui.frame_requester(),
            app_event_tx: self.app_event_tx.clone(),
            initial_prompt: None,
            initial_images: Vec::new(),
            enhanced_keys_supported: self.enhanced_keys_supported,
            auth_manager: self.auth_manager.clone(),
        };

        self.chat_widget =
            ChatWidget::new_from_existing(init, resumed.conversation, resumed.session_configured);
        self.transcript_lines.clear();
        self.deferred_history_lines.clear();
        self.has_emitted_history_lines = false;
        self.overlay = None;
        self.backtrack = BacktrackState::default();
        self.clear_auto_checkpoint_queue();
        tui.frame_requester().schedule_frame();

        self.chat_widget
            .add_info_message(format!("Loaded checkpoint {}", path.display()), None);
        Ok(())
    }

    async fn try_handle_pending_history_request(
        &mut self,
        tui: &mut tui::Tui,
        ev: &codex_core::protocol::ConversationPathResponseEvent,
    ) -> Result<bool> {
        let Some(request) = self.pending_history_request.take() else {
            return Ok(false);
        };

        if request.conversation_id() != &ev.conversation_id {
            self.pending_history_request = Some(request);
            return Ok(false);
        }

        match request {
            HistoryRequest::Pop { drop_count, .. } => {
                self.handle_history_pop(tui, ev, drop_count).await?;
            }
            HistoryRequest::Retry {
                drop_count,
                message,
                ..
            } => {
                self.handle_history_retry(tui, ev, drop_count, message)
                    .await?;
            }
            HistoryRequest::Save { target, .. } => {
                self.handle_history_save(ev, target).await?;
            }
            HistoryRequest::AutoSave { target, .. } => {
                self.handle_history_auto_save(ev, target).await?;
            }
        }
        self.try_start_auto_checkpoint();
        Ok(true)
    }

    async fn handle_history_pop(
        &mut self,
        tui: &mut tui::Tui,
        ev: &codex_core::protocol::ConversationPathResponseEvent,
        drop_count: usize,
    ) -> Result<()> {
        let cfg = self.chat_widget.config_ref().clone();
        match self
            .perform_fork(ev.path.clone(), drop_count, cfg.clone())
            .await
        {
            Ok(new_conv) => {
                self.install_forked_conversation(tui, cfg, new_conv, drop_count, "");
                self.chat_widget.add_info_message(
                    "Removed the latest turn from the conversation context.".to_string(),
                    None,
                );
            }
            Err(err) => {
                self.chat_widget
                    .add_error_message(format!("Failed to pop last turn: {err}"));
            }
        }
        Ok(())
    }

    async fn handle_history_retry(
        &mut self,
        tui: &mut tui::Tui,
        ev: &codex_core::protocol::ConversationPathResponseEvent,
        drop_count: usize,
        message: String,
    ) -> Result<()> {
        let cfg = self.chat_widget.config_ref().clone();
        match self
            .perform_fork(ev.path.clone(), drop_count, cfg.clone())
            .await
        {
            Ok(new_conv) => {
                self.install_forked_conversation(tui, cfg, new_conv, drop_count, "");
                self.chat_widget
                    .add_info_message("Retrying the latest user message.".to_string(), None);
                self.chat_widget.submit_text_message(message);
            }
            Err(err) => {
                self.chat_widget
                    .add_error_message(format!("Failed to retry last turn: {err}"));
            }
        }
        Ok(())
    }

    async fn handle_history_save(
        &mut self,
        ev: &codex_core::protocol::ConversationPathResponseEvent,
        target: PathBuf,
    ) -> Result<()> {
        match tokio::fs::copy(&ev.path, &target).await {
            Ok(_) => {
                self.chat_widget
                    .add_info_message(format!("Saved checkpoint to {}", target.display()), None);
            }
            Err(err) => {
                self.chat_widget.add_error_message(format!(
                    "Failed to save checkpoint to {}: {err}",
                    target.display()
                ));
            }
        }
        Ok(())
    }

    async fn handle_history_auto_save(
        &mut self,
        ev: &codex_core::protocol::ConversationPathResponseEvent,
        target: PathBuf,
    ) -> Result<()> {
        if self.config.auto_checkpoint_keep == 0 {
            return Ok(());
        }

        if let Some(parent) = target.parent()
            && let Err(err) = tokio::fs::create_dir_all(parent).await
        {
            tracing::error!(
                "failed to create auto checkpoint directory {}: {err}",
                parent.display()
            );
            return Ok(());
        }

        match tokio::fs::copy(&ev.path, &target).await {
            Ok(_) => {
                if let Err(err) = self.prune_old_auto_checkpoints().await {
                    tracing::error!("failed to prune auto checkpoints: {err:?}");
                }
            }
            Err(err) => {
                self.chat_widget.add_error_message(format!(
                    "Failed to write auto checkpoint {}: {err}",
                    target.display()
                ));
            }
        }
        Ok(())
    }

    async fn prune_old_auto_checkpoints(&mut self) -> Result<()> {
        if self.config.auto_checkpoint_keep == 0 {
            return Ok(());
        }

        let mut dir = self.config.codex_home.clone();
        dir.push("saves");

        let mut autos: Vec<(SystemTime, PathBuf)> = Vec::new();
        match tokio::fs::read_dir(&dir).await {
            Ok(mut rd) => {
                while let Some(entry) = rd.next_entry().await? {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    if !is_auto_checkpoint_path(&path) {
                        continue;
                    }
                    let metadata = entry.metadata().await?;
                    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    autos.push((modified, path));
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => {
                return Err(err.into());
            }
        }

        autos.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, path) in autos.into_iter().skip(self.config.auto_checkpoint_keep) {
            if let Err(err) = tokio::fs::remove_file(&path).await
                && err.kind() != ErrorKind::NotFound
            {
                self.chat_widget.add_error_message(format!(
                    "Failed to prune auto checkpoint {}: {err}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn collect_transcript_lines(&self) -> Vec<String> {
        self.transcript_lines
            .iter()
            .chain(self.deferred_history_lines.iter())
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    fn generate_save_path(&self, conversation_id: &ConversationId) -> PathBuf {
        let mut dir = self.config.codex_home.clone();
        dir.push("saves");
        let sanitized = sanitize_filename_component(&conversation_id.to_string());
        let now = Utc::now();
        let filename = format!(
            "save-{}{:03}-{sanitized}.jsonl",
            now.format("%Y%m%d-%H%M%S"),
            now.timestamp_subsec_millis()
        );
        dir.join(filename)
    }

    fn generate_auto_save_path(&self, conversation_id: &ConversationId) -> PathBuf {
        let mut dir = self.config.codex_home.clone();
        dir.push("saves");
        let sanitized = sanitize_filename_component(&conversation_id.to_string());
        let now = Utc::now();
        let filename = format!(
            "autosave-{}{:03}-{sanitized}.jsonl",
            now.format("%Y%m%d-%H%M%S"),
            now.timestamp_subsec_millis()
        );
        dir.join(filename)
    }

    async fn list_saved_checkpoints(&self) -> Result<Vec<SaveEntry>> {
        let mut dir = self.config.codex_home.clone();
        dir.push("saves");

        let mut entries: Vec<SaveEntry> = Vec::new();
        match tokio::fs::read_dir(&dir).await {
            Ok(mut rd) => {
                while let Some(entry) = rd.next_entry().await? {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
                        continue;
                    }
                    let metadata = entry.metadata().await?;
                    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    let kind = if is_auto_checkpoint_path(&path) {
                        SaveEntryKind::Auto
                    } else {
                        SaveEntryKind::Manual
                    };
                    let display_name = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default()
                        .to_string();
                    let timestamp = chrono::DateTime::<Utc>::from(modified);
                    let description = match kind {
                        SaveEntryKind::Auto => Some(format!(
                            "Autosave • Modified {}",
                            timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                        )),
                        SaveEntryKind::Manual => Some(format!(
                            "Modified {}",
                            timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                        )),
                    };
                    entries.push(SaveEntry {
                        path,
                        display: display_name,
                        description,
                        modified,
                        kind,
                    });
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(err) => {
                return Err(err.into());
            }
        }

        entries.sort_by(|a, b| b.modified.cmp(&a.modified));
        Ok(entries)
    }
}

fn sanitize_filename_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn is_auto_checkpoint_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|name| name.starts_with("autosave-"))
        .unwrap_or(false)
}

struct SaveEntry {
    path: PathBuf,
    display: String,
    description: Option<String>,
    modified: SystemTime,
    kind: SaveEntryKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SaveEntryKind {
    Manual,
    Auto,
}

struct AutoCheckpointRequest {
    conversation_id: ConversationId,
    target: PathBuf,
}

enum HistoryRequest {
    Pop {
        conversation_id: ConversationId,
        drop_count: usize,
    },
    Retry {
        conversation_id: ConversationId,
        drop_count: usize,
        message: String,
    },
    Save {
        conversation_id: ConversationId,
        target: PathBuf,
    },
    AutoSave {
        conversation_id: ConversationId,
        target: PathBuf,
    },
}

impl HistoryRequest {
    fn conversation_id(&self) -> &ConversationId {
        match self {
            HistoryRequest::Pop {
                conversation_id, ..
            }
            | HistoryRequest::Retry {
                conversation_id, ..
            }
            | HistoryRequest::Save {
                conversation_id, ..
            }
            | HistoryRequest::AutoSave {
                conversation_id, ..
            } => conversation_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_backtrack::BacktrackState;
    use crate::app_event::AppEvent;
    use crate::chatwidget::tests::make_chatwidget_manual_with_sender;
    use crate::file_search::FileSearchManager;
    use codex_core::AuthManager;
    use codex_core::CodexAuth;
    use codex_core::ConversationManager;
    use codex_core::protocol::Event;
    use codex_core::protocol::EventMsg;
    use codex_core::protocol::Op;
    use codex_core::protocol::SessionConfiguredEvent;
    use codex_protocol::mcp_protocol::ConversationId;
    use ratatui::text::Line;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tempfile::TempPath;
    use tokio::runtime::Runtime;
    use tokio::sync::mpsc::UnboundedReceiver;

    fn make_test_app_with_channels() -> (App, UnboundedReceiver<AppEvent>, UnboundedReceiver<Op>) {
        let (chat_widget, app_event_tx, rx, op_rx) = make_chatwidget_manual_with_sender();
        let config = chat_widget.config_ref().clone();

        let server = Arc::new(ConversationManager::with_auth(CodexAuth::from_api_key(
            "Test API Key",
        )));
        let auth_manager =
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("Test API Key"));
        let file_search = FileSearchManager::new(config.cwd.clone(), app_event_tx.clone());

        let app = App {
            server,
            app_event_tx,
            chat_widget,
            auth_manager,
            config,
            active_profile: None,
            file_search,
            transcript_lines: Vec::<Line<'static>>::new(),
            overlay: None,
            deferred_history_lines: Vec::new(),
            has_emitted_history_lines: false,
            enhanced_keys_supported: false,
            commit_anim_running: Arc::new(AtomicBool::new(false)),
            backtrack: BacktrackState::default(),
            pending_history_request: None,
            queued_auto_checkpoint: None,
        };

        (app, rx, op_rx)
    }

    fn make_test_app() -> App {
        let (app, _event_rx, _op_rx) = make_test_app_with_channels();
        app
    }

    fn drain_app_events(rx: &mut UnboundedReceiver<AppEvent>) {
        while rx.try_recv().is_ok() {}
    }

    fn drain_ops(rx: &mut UnboundedReceiver<Op>) {
        while rx.try_recv().is_ok() {}
    }

    fn configure_session(app: &mut App, conversation_id: ConversationId) -> TempPath {
        let rollout = tempfile::NamedTempFile::new().expect("create rollout temp file");
        let temp_path = rollout.into_temp_path();
        let event = SessionConfiguredEvent {
            session_id: conversation_id,
            model: "test-model".to_string(),
            reasoning_effort: None,
            history_log_id: 0,
            history_entry_count: 0,
            initial_messages: None,
            rollout_path: temp_path.to_path_buf(),
        };
        app.chat_widget.handle_codex_event(Event {
            id: "session-configured".to_string(),
            msg: EventMsg::SessionConfigured(event),
        });
        temp_path
    }

    fn line(text: &str) -> Line<'static> {
        text.to_string().into()
    }

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn update_reasoning_effort_updates_config() {
        let mut app = make_test_app();
        app.config.model_reasoning_effort = Some(ReasoningEffortConfig::Medium);
        app.chat_widget
            .set_reasoning_effort(Some(ReasoningEffortConfig::Medium));

        app.on_update_reasoning_effort(Some(ReasoningEffortConfig::High));

        assert_eq!(
            app.config.model_reasoning_effort,
            Some(ReasoningEffortConfig::High)
        );
        assert_eq!(
            app.chat_widget.config_ref().model_reasoning_effort,
            Some(ReasoningEffortConfig::High)
        );
    }

    #[test]
    fn pop_last_turn_sets_pending_request() {
        let (mut app, mut event_rx, mut op_rx) = make_test_app_with_channels();
        let conversation_id = ConversationId::new();
        let _rollout = configure_session(&mut app, conversation_id);
        drain_app_events(&mut event_rx);
        drain_ops(&mut op_rx);

        app.transcript_lines = vec![
            line("user"),
            line("question to drop"),
            line(""),
            line("assistant"),
            line("an answer"),
            line(""),
        ];

        let rt = Runtime::new().expect("create runtime");
        rt.block_on(app.handle_pop_last_turn())
            .expect("pop last turn");

        match app.pending_history_request {
            Some(HistoryRequest::Pop {
                conversation_id: id,
                drop_count,
            }) => {
                assert_eq!(id, conversation_id);
                assert_eq!(drop_count, 1);
            }
            _ => panic!("expected pending pop request"),
        }

        let op = op_rx.try_recv().expect("expected GetPath op");
        assert!(matches!(op, Op::GetPath));
    }

    #[test]
    fn retry_last_turn_captures_message_text() {
        let (mut app, mut event_rx, mut op_rx) = make_test_app_with_channels();
        let conversation_id = ConversationId::new();
        let _rollout = configure_session(&mut app, conversation_id);
        drain_app_events(&mut event_rx);
        drain_ops(&mut op_rx);

        app.transcript_lines = vec![
            line("user"),
            line("retry this please"),
            line(""),
            line("assistant"),
            line("earlier answer"),
            line(""),
        ];

        let rt = Runtime::new().expect("create runtime");
        rt.block_on(app.handle_retry_last_turn())
            .expect("retry last turn");

        match app.pending_history_request {
            Some(HistoryRequest::Retry {
                conversation_id: id,
                drop_count,
                ref message,
            }) => {
                assert_eq!(id, conversation_id);
                assert_eq!(drop_count, 1);
                assert_eq!(message, "retry this please");
            }
            _ => panic!("expected pending retry request"),
        }

        let op = op_rx.try_recv().expect("expected GetPath op");
        assert!(matches!(op, Op::GetPath));
    }

    #[test]
    fn save_checkpoint_builds_target_path() {
        let (mut app, mut event_rx, mut op_rx) = make_test_app_with_channels();
        let conversation_id = ConversationId::new();
        let _rollout = configure_session(&mut app, conversation_id);
        drain_app_events(&mut event_rx);
        drain_ops(&mut op_rx);

        let temp_dir = tempfile::tempdir().expect("create temp codex home");
        app.config.codex_home = temp_dir.path().to_path_buf();

        let rt = Runtime::new().expect("create runtime");
        rt.block_on(app.handle_save_checkpoint())
            .expect("save checkpoint");

        let target = match app.pending_history_request {
            Some(HistoryRequest::Save { ref target, .. }) => target.clone(),
            _ => panic!("expected save request"),
        };

        assert!(target.starts_with(temp_dir.path()));
        assert!(target.extension().and_then(|s| s.to_str()) == Some("jsonl"));

        let op = op_rx.try_recv().expect("expected GetPath op");
        assert!(matches!(op, Op::GetPath));
    }

    #[test]
    fn auto_checkpoint_sets_pending_request() {
        let (mut app, mut event_rx, mut op_rx) = make_test_app_with_channels();
        let conversation_id = ConversationId::new();
        let _rollout = configure_session(&mut app, conversation_id);
        drain_app_events(&mut event_rx);
        drain_ops(&mut op_rx);

        app.config.auto_checkpoint_keep = 3;
        app.queue_auto_checkpoint();

        match app.pending_history_request {
            Some(HistoryRequest::AutoSave {
                conversation_id: id,
                ref target,
            }) => {
                assert_eq!(id, conversation_id);
                let file_name = target
                    .file_name()
                    .and_then(|s| s.to_str())
                    .expect("auto save filename");
                assert!(file_name.starts_with("autosave-"));
                assert_eq!(target.extension().and_then(|s| s.to_str()), Some("jsonl"));
            }
            _ => panic!("expected auto save request"),
        }

        let op = op_rx.try_recv().expect("expected GetPath op");
        assert!(matches!(op, Op::GetPath));
    }

    #[test]
    fn export_transcript_writes_markdown_snapshot() {
        let (mut app, mut event_rx, _op_rx) = make_test_app_with_channels();
        app.transcript_lines = vec![
            line("user"),
            line("export this message"),
            line(""),
            line("assistant"),
            line("response body"),
            line(""),
        ];

        drain_app_events(&mut event_rx);

        let rt = Runtime::new().expect("create runtime");
        rt.block_on(app.export_transcript())
            .expect("export transcript");

        let mut exported_path: Option<PathBuf> = None;
        while let Ok(event) = event_rx.try_recv() {
            if let AppEvent::InsertHistoryCell(cell) = event {
                let line_text = cell
                    .display_lines(120)
                    .first()
                    .map(line_to_string)
                    .unwrap_or_default();
                if let Some((_, path_part)) = line_text
                    .trim_start_matches("> ")
                    .split_once("Exported transcript to ")
                {
                    exported_path = Some(PathBuf::from(path_part.trim()));
                    break;
                }
            }
        }

        let exported_path = exported_path.expect("expected export path in info message");
        assert!(exported_path.exists(), "export file should exist");
        let contents = fs::read_to_string(&exported_path).expect("read export file");
        assert!(contents.contains("# Codex Transcript Export"));
        assert!(contents.contains("export this message"));
        assert!(contents.contains("response body"));

        fs::remove_file(exported_path).expect("clean up export file");
    }
}
