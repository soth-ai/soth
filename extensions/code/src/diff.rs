//! Line-count delta helper for `file_write` payloads.
//!
//! Direct port of the gryph PR #21/#22 lesson: `SplitLines("")` (Go
//! difflib) returns `[""]` not `[]` for empty inputs, which made every
//! "create new file" event look like it had 1 unchanged line. Same trap
//! exists with naive `str::split('\n').count()`. This helper
//! special-cases empty sides explicitly.

/// Compute `(lines_added, lines_removed)` between optional old and new
/// content. Both `None` and empty-string are treated identically — there
/// is no "no content" vs "empty content" distinction at the line level.
///
/// - `(None, Some("a\nb"))` → `(2, 0)` (file created)
/// - `(Some("a\nb"), None)` → `(0, 2)` (file deleted)
/// - `(Some("a\nb"), Some("a\nb\nc"))` → `(1, 0)` (one line appended)
/// - `(Some("a\nb"), Some("a\nb"))` → `(0, 0)` (no-op)
/// - `(None, None)` → `(0, 0)` (no payload — caller may then stat the file)
pub fn line_count_delta(old: Option<&str>, new: Option<&str>) -> (u32, u32) {
    let old_lines = count_lines(old);
    let new_lines = count_lines(new);
    if old_lines == new_lines && contents_equal(old, new) {
        // Same content — no deltas. (When sizes match but content
        // differs, fall through to the diff branch below.)
        return (0, 0);
    }
    if old_lines == 0 {
        return (new_lines, 0);
    }
    if new_lines == 0 {
        return (0, old_lines);
    }
    // Coarse approximation when both sides have content: count the
    // strict size delta as added or removed. A line-by-line LCS diff
    // would be more accurate but this is a Phase-1 surface — refine
    // when the dashboard surfaces per-file diffs.
    if new_lines > old_lines {
        (new_lines - old_lines, 0)
    } else if old_lines > new_lines {
        (0, old_lines - new_lines)
    } else {
        // Same line count, different content — call it a "0/0" since
        // we can't know which lines changed without an LCS pass.
        (0, 0)
    }
}

/// Count newline-delimited lines in `s`. `None` and `Some("")` both
/// return 0 — gryph PR #21/#22's bug was in not collapsing those cases.
fn count_lines(s: Option<&str>) -> u32 {
    match s {
        None => 0,
        Some(t) if t.is_empty() => 0,
        Some(t) => t.lines().count() as u32,
    }
}

fn contents_equal(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x == y,
        (None, Some(s)) | (Some(s), None) => s.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_old_treated_as_create() {
        assert_eq!(line_count_delta(None, Some("a\nb\nc")), (3, 0));
        assert_eq!(line_count_delta(Some(""), Some("a\nb\nc")), (3, 0));
    }

    #[test]
    fn empty_new_treated_as_delete() {
        assert_eq!(line_count_delta(Some("a\nb\nc"), None), (0, 3));
        assert_eq!(line_count_delta(Some("a\nb\nc"), Some("")), (0, 3));
    }

    #[test]
    fn both_empty_is_zero() {
        // The trap from gryph PR #21: SplitLines("") returns [""] not [].
        // Empty sides must collapse to (0, 0), not (1, 1) or (1, 0).
        assert_eq!(line_count_delta(None, None), (0, 0));
        assert_eq!(line_count_delta(Some(""), Some("")), (0, 0));
        assert_eq!(line_count_delta(None, Some("")), (0, 0));
        assert_eq!(line_count_delta(Some(""), None), (0, 0));
    }

    #[test]
    fn append_only_adds_lines() {
        assert_eq!(line_count_delta(Some("a\nb"), Some("a\nb\nc")), (1, 0));
    }

    #[test]
    fn truncate_only_removes_lines() {
        assert_eq!(line_count_delta(Some("a\nb\nc"), Some("a")), (0, 2));
    }

    #[test]
    fn identical_content_is_zero() {
        assert_eq!(line_count_delta(Some("a\nb\nc"), Some("a\nb\nc")), (0, 0));
    }

    #[test]
    fn same_size_different_content_is_zero_zero() {
        // Without an LCS pass we can't quantify this — and we'd rather
        // under-report than guess. Acceptable for the Phase-1 surface.
        assert_eq!(line_count_delta(Some("a\nb"), Some("x\ny")), (0, 0));
    }

    #[test]
    fn single_line_no_trailing_newline() {
        assert_eq!(line_count_delta(None, Some("hello")), (1, 0));
        assert_eq!(line_count_delta(Some("hello"), Some("hello\nworld")), (1, 0));
    }
}
