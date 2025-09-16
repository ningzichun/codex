use ratatui::style::Style;
use ratatui::text::Line;

/// Convenience: compute the highlight range for the Nth last user message.
pub(crate) fn highlight_range_for_nth_last_user(
    lines: &[Line<'_>],
    n: usize,
) -> Option<(usize, usize)> {
    let header = find_nth_last_user_header_index(lines, n)?;
    Some(highlight_range_from_header(lines, header))
}

/// Compute the wrapped display-line offset before `header_idx`, for a given width.
pub(crate) fn wrapped_offset_before(lines: &[Line<'_>], header_idx: usize, width: u16) -> usize {
    let before = &lines[0..header_idx];
    crate::wrapping::word_wrap_lines(before, width as usize).len()
}

/// Find the header index for the Nth last user message in the transcript.
/// Returns `None` if `n == 0` or there are fewer than `n` user messages.
pub(crate) fn find_nth_last_user_header_index(lines: &[Line<'_>], n: usize) -> Option<usize> {
    if n == 0 {
        return None;
    }
    let mut found = 0usize;
    for (idx, line) in lines.iter().enumerate().rev() {
        let content: String = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<Vec<_>>()
            .join("");
        if content.trim() == "user" {
            found += 1;
            if found == n {
                return Some(idx);
            }
        }
    }
    None
}

/// Normalize a requested backtrack step `n` against the available user messages.
/// - Returns `0` if there are no user messages.
/// - Returns `n` if the Nth last user message exists.
/// - Otherwise wraps to `1` (the most recent user message).
pub(crate) fn normalize_backtrack_n(lines: &[Line<'_>], n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    if find_nth_last_user_header_index(lines, n).is_some() {
        return n;
    }
    if find_nth_last_user_header_index(lines, 1).is_some() {
        1
    } else {
        0
    }
}

/// Extract the text content of the Nth last user message.
/// The message body is considered to be the lines following the "user" header
/// until the first blank line.
pub(crate) fn nth_last_user_text(lines: &[Line<'_>], n: usize) -> Option<String> {
    let header_idx = find_nth_last_user_header_index(lines, n)?;
    let body = message_body_lines(lines, header_idx);
    if body.is_empty() {
        None
    } else {
        Some(body.join("\n"))
    }
}

/// Extract message text starting after `header_idx` until the first blank line.
fn message_body_lines(lines: &[Line<'_>], header_idx: usize) -> Vec<String> {
    let mut body: Vec<String> = Vec::new();
    let mut pending_blanks: usize = 0;
    let mut ended_by_header = false;

    for line in lines.iter().skip(header_idx + 1) {
        if is_header_line(line) {
            ended_by_header = true;
            break;
        }

        if is_blank_line(line) {
            pending_blanks += 1;
            continue;
        }

        for _ in 0..pending_blanks {
            body.push(String::new());
        }
        pending_blanks = 0;

        let text = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>();
        body.push(text);
    }

    if !ended_by_header {
        for _ in 0..pending_blanks {
            body.push(String::new());
        }
    }

    body
}

fn is_blank_line(line: &Line<'_>) -> bool {
    line.spans
        .iter()
        .all(|s| s.content.as_ref().trim().is_empty())
}

fn is_header_line(line: &Line<'_>) -> bool {
    let Some(first) = line.spans.first() else {
        return false;
    };

    let text = first.content.as_ref().trim();
    if text.is_empty() {
        return false;
    }

    if matches!(text, "user" | "codex") && first.style != Style::default() {
        return true;
    }

    if first.style != Style::default() {
        return true;
    }

    line.spans.len() > 1
}

/// Given a header index, return the inclusive range for the message block
/// [header_idx, end) where end is the first blank line after the header or the
/// end of the transcript.
fn highlight_range_from_header(lines: &[Line<'_>], header_idx: usize) -> (usize, usize) {
    let body_len = message_body_lines(lines, header_idx).len();
    let end = (header_idx + 1 + body_len).min(lines.len());
    (header_idx, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Stylize;

    fn line(s: &str) -> Line<'static> {
        s.to_string().into()
    }

    fn user_header() -> Line<'static> {
        "user".cyan().bold().into()
    }

    fn codex_header() -> Line<'static> {
        "codex".magenta().bold().into()
    }

    fn transcript_with_users(count: usize) -> Vec<Line<'static>> {
        // Build a transcript with `count` user messages, each followed by one body line and a blank line.
        let mut v = Vec::new();
        for i in 0..count {
            v.push(user_header());
            v.push(line(&format!("message {i}")));
            v.push(line(""));
        }
        v
    }

    #[test]
    fn normalize_wraps_to_one_when_past_oldest() {
        let lines = transcript_with_users(2);
        assert_eq!(normalize_backtrack_n(&lines, 1), 1);
        assert_eq!(normalize_backtrack_n(&lines, 2), 2);
        // Requesting 3rd when only 2 exist wraps to 1
        assert_eq!(normalize_backtrack_n(&lines, 3), 1);
    }

    #[test]
    fn normalize_returns_zero_when_no_user_messages() {
        let lines = transcript_with_users(0);
        assert_eq!(normalize_backtrack_n(&lines, 1), 0);
        assert_eq!(normalize_backtrack_n(&lines, 5), 0);
    }

    #[test]
    fn normalize_keeps_valid_n() {
        let lines = transcript_with_users(3);
        assert_eq!(normalize_backtrack_n(&lines, 2), 2);
    }

    #[test]
    fn nth_last_user_text_preserves_blank_lines() {
        let lines = vec![
            user_header(),
            line("1 2 3 4 5"),
            line("6 7"),
            line(""),
            line("8 9"),
            line(""),
            line("10"),
            Line::from(""),
            codex_header(),
        ];

        let text = nth_last_user_text(&lines, 1).expect("message");
        assert_eq!(text, "1 2 3 4 5\n6 7\n\n8 9\n\n10");
    }

    #[test]
    fn highlight_range_includes_lines_after_blank() {
        let lines = vec![
            user_header(),
            line("alpha"),
            line("beta"),
            line(""),
            line("gamma"),
            Line::from(""),
            codex_header(),
        ];

        let (start, end) = highlight_range_for_nth_last_user(&lines, 1).expect("range");
        assert_eq!(start, 0);
        assert_eq!(end, 5);
    }
}
