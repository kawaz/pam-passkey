//! Showing strings that come from the caller's process chain (argv, paths, user names), which
//! are untrusted: in the Touch ID dialog and in what `send_command` is told.

/// Control characters, the line and paragraph separators and format characters as `\u{XXXX}`,
/// so that the string stays on its line and cannot reorder or hide what is shown around it.
pub fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') || is_format(ch) {
            escaped.push_str(&format!("\\u{{{:04X}}}", u32::from(ch)));
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

/// Format characters (Unicode Cf: zero-width spaces and joiners, bidi controls, the soft hyphen,
/// tag characters, …).
fn is_format(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each class that could break a line or reorder the text around it becomes a visible escape;
    // ordinary text, including non-ASCII and emoji, is kept as it is.
    #[test]
    fn escapes_controls_separators_and_format_characters() {
        assert_eq!(
            escape("a\nb\tc\u{7f}\u{85}"),
            r"a\u{000A}b\u{0009}c\u{007F}\u{0085}"
        );
        assert_eq!(escape("x\u{2028}y\u{2029}"), r"x\u{2028}y\u{2029}");
        assert_eq!(
            escape("abc\u{202E}fed\u{2066}\u{200B}\u{FEFF}\u{E0041}"),
            r"abc\u{202E}fed\u{2066}\u{200B}\u{FEFF}\u{E0041}"
        );
        assert_eq!(escape("é 全角\u{3000}🟢 '\""), "é 全角\u{3000}🟢 '\"");
    }
}
