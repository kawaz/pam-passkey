//! The Touch ID dialog's text (`localizedReason`, DR-0004 ダイアログの本文), built from the
//! process chain the PAM module collected. Shared by the module, which shows it, and by
//! `_probe-dialog`, which shows the same text for a chain given to it.
//!
//! The OS puts its own lead-in (「<プロセス名> で次の操作を実行しようとしています:」) before the
//! text and wraps it at a fixed width of about 34 half-width columns, growing the dialog
//! downwards. Every string from the chain (argv, paths, user names) is untrusted.

use crate::ProcessDetails;

/// Width of an ancestor's row in half-width columns, prefix included. Rows that fit stay on one
/// line of the dialog.
pub const ANCESTOR_COLUMNS: usize = 30;
/// Columns an ancestor's command keeps however deep its row is indented.
const MIN_COMMAND_COLUMNS: usize = 8;
/// A longer chain shows its first `HEAD_ROWS` and last `TAIL_ROWS` rows around one `…` row.
pub const HEAD_ROWS: usize = 2;
pub const TAIL_ROWS: usize = 4;
/// The caller's row is shown whole up to this many characters (the dialog's own limits on a
/// very long text are unobserved), then shortened in the middle.
pub const CALLER_MAX_CHARS: usize = 400;
/// The working directory is shortened in the middle beyond this many characters.
pub const CWD_MAX_CHARS: usize = 200;
/// Marks the caller's row.
const CALLER_MARK: &str = "⭐";

/// The dialog text: an empty line after the OS lead-in, then the caller's working directory and
/// its ancestors from launchd down to the caller. `processes` is the chain as collected (caller
/// first); `user_name` names a uid; `fallback` names the caller when the chain is empty.
pub fn reason(
    processes: &[ProcessDetails],
    user_name: impl Fn(u32) -> Option<String>,
    fallback: &str,
) -> String {
    let cwd = processes
        .first()
        .and_then(|caller| caller.cwd.as_deref())
        .map(|cwd| shorten_middle(&escape(cwd), CWD_MAX_CHARS))
        .unwrap_or_else(|| "?".to_owned());
    format!(
        "\n\n# cwd:\n{cwd}\n\n# ancestors:\n{}",
        ancestor_rows(processes, &user_name, fallback).join("\n")
    )
}

fn ancestor_rows(
    processes: &[ProcessDetails],
    user_name: &impl Fn(u32) -> Option<String>,
    fallback: &str,
) -> Vec<String> {
    let Some((caller, ancestors)) = processes.split_first() else {
        return vec![format!("{CALLER_MARK} {}", escape(fallback))];
    };
    // launchd first, the caller's parent last.
    let ancestors: Vec<&ProcessDetails> = ancestors.iter().rev().collect();
    let total = ancestors.len() + 1;
    let mut shown: Vec<Option<&ProcessDetails>> = if total > HEAD_ROWS + 1 + TAIL_ROWS {
        let tail_ancestors = TAIL_ROWS - 1;
        ancestors[..HEAD_ROWS]
            .iter()
            .map(|process| Some(*process))
            .chain(std::iter::once(None))
            .chain(
                ancestors[ancestors.len() - tail_ancestors..]
                    .iter()
                    .map(|process| Some(*process)),
            )
            .collect()
    } else {
        ancestors.iter().map(|process| Some(*process)).collect()
    };
    shown.push(Some(caller));
    let last = shown.len() - 1;
    shown
        .iter()
        .enumerate()
        .map(|(row, process)| {
            let prefix = branch(row);
            match process {
                None => format!("{prefix}…"),
                Some(process) if row == last => {
                    let command = command_of(process)
                        .map(|argv| escape(&argv.join(" ")))
                        .unwrap_or_else(|| escape(fallback));
                    format!(
                        "{CALLER_MARK} {prefix}{} {}",
                        identity(process, user_name),
                        shorten_middle(&command, CALLER_MAX_CHARS)
                    )
                }
                Some(process) => {
                    let head = format!("{prefix}{} ", identity(process, user_name));
                    let budget = ANCESTOR_COLUMNS
                        .saturating_sub(width(&head))
                        .max(MIN_COMMAND_COLUMNS);
                    let command = command_of(process)
                        .map(|argv| fit_command(&argv, budget))
                        .unwrap_or_else(|| "?".to_owned());
                    format!("{head}{command}")
                }
            }
        })
        .collect()
}

/// pstree-like branch of the row-th row: `- ` for the first, then `\- ` one space deeper each.
fn branch(row: usize) -> String {
    match row {
        0 => "- ".to_owned(),
        _ => format!("{}\\- ", " ".repeat(row - 1)),
    }
}

/// `<pid, 5 digits> <user>`; the uid itself when it has no name.
fn identity(process: &ProcessDetails, user_name: &impl Fn(u32) -> Option<String>) -> String {
    let user = user_name(process.uid).unwrap_or_else(|| process.uid.to_string());
    format!("{:05} {}", process.pid, escape(&user))
}

/// argv when known, otherwise the executable path alone.
fn command_of(process: &ProcessDetails) -> Option<Vec<String>> {
    process
        .argv
        .clone()
        .filter(|argv| argv.first().is_some_and(|first| !first.is_empty()))
        .or_else(|| process.path.clone().map(|path| vec![path]))
}

/// An ancestor's command within `budget` columns. The executable's name matters most, so the
/// directories of argv[0] go first (`…/ghostty`), then the end is cut.
fn fit_command(argv: &[String], budget: usize) -> String {
    let whole = escape(&argv.join(" "));
    if width(&whole) <= budget {
        return whole;
    }
    let (dash, program) = match argv[0].strip_prefix('-') {
        Some(program) => ("-", program),
        None => ("", argv[0].as_str()),
    };
    let text = match program.rsplit_once('/') {
        Some((directories, name)) if !directories.is_empty() && !name.is_empty() => {
            let short = std::iter::once(format!("{dash}…/{name}"))
                .chain(argv[1..].iter().cloned())
                .collect::<Vec<_>>()
                .join(" ");
            escape(&short)
        }
        _ => whole,
    };
    cut_end(&text, budget)
}

fn cut_end(text: &str, budget: usize) -> String {
    if width(text) <= budget {
        return text.to_owned();
    }
    let mut kept = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let next = used + char_width(ch);
        if next + 1 > budget {
            break;
        }
        kept.push(ch);
        used = next;
    }
    kept.push('…');
    kept
}

fn shorten_middle(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.to_owned();
    }
    let keep = max - 1;
    let head = keep.div_ceil(2);
    let tail = keep / 2;
    chars[..head]
        .iter()
        .chain(std::iter::once(&'…'))
        .chain(&chars[chars.len() - tail..])
        .collect()
}

fn is_bidi_control(ch: char) -> bool {
    matches!(ch, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Control characters, the line and paragraph separators and bidi controls as `\u{XXXX}`, so
/// that no string from the chain can break a row, fake the layout or reorder what is shown.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') || is_bidi_control(ch) {
            escaped.push_str(&format!("\\u{{{:04X}}}", u32::from(ch)));
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

/// Approximate columns of a character: 2 for East Asian wide and emoji ranges, 1 otherwise.
fn char_width(ch: char) -> usize {
    match u32::from(ch) {
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x2B50
        | 0x1F300..=0x1FAFF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

fn width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, uid: u32, path: &str, argv: &[&str]) -> ProcessDetails {
        ProcessDetails {
            pid,
            uid,
            cwd: Some("/Users/kawaz/work".into()),
            path: Some(path.into()),
            argv: Some(argv.iter().map(|arg| (*arg).to_owned()).collect()),
            signing_id: None,
            team_id: None,
            signer: None,
        }
    }

    fn names(uid: u32) -> Option<String> {
        match uid {
            0 => Some("root".into()),
            501 => Some("kawaz".into()),
            _ => None,
        }
    }

    /// The chain of a sudo typed in a terminal, caller first as the module collects it.
    fn terminal_chain() -> Vec<ProcessDetails> {
        vec![
            process(79807, 0, "/usr/bin/sudo", &["sudo", "-k", "true"]),
            process(26725, 501, "/bin/zsh", &["-/bin/zsh"]),
            process(
                26724,
                0,
                "/usr/bin/login",
                &[
                    "/usr/bin/login",
                    "-flp",
                    "kawaz",
                    "/bin/bash",
                    "--noprofile",
                ],
            ),
            process(
                7734,
                501,
                "/Applications/Ghostty.app/Contents/MacOS/ghostty",
                &["/Applications/Ghostty.app/Contents/MacOS/ghostty"],
            ),
            process(1, 0, "/sbin/launchd", &["/sbin/launchd"]),
        ]
    }

    fn rows(text: &str) -> Vec<&str> {
        text.split_once("# ancestors:\n")
            .unwrap()
            .1
            .lines()
            .collect()
    }

    // The text is its own paragraph after the OS lead-in, then the cwd and the chain from launchd
    // down to the marked caller, which is shown whole.
    #[test]
    fn terminal_sudo_shows_cwd_and_the_chain() {
        assert_eq!(
            reason(&terminal_chain(), names, "sudo"),
            "\n\n# cwd:\n/Users/kawaz/work\n\n# ancestors:\n\
             - 00001 root /sbin/launchd\n\
             \\- 07734 kawaz …/ghostty\n \
             \\- 26724 root …/login -flp k…\n  \
             \\- 26725 kawaz -/bin/zsh\n\
             ⭐    \\- 79807 root sudo -k true"
        );
    }

    // Every ancestor's row fits the dialog's line; the caller's row is never cut.
    #[test]
    fn ancestor_rows_fit_the_width() {
        let mut chain = terminal_chain();
        chain[0].argv = Some(vec!["sudo".into(), "x".repeat(150)]);
        let text = reason(&chain, names, "sudo");
        let rows = rows(&text);
        for row in &rows[..rows.len() - 1] {
            assert!(width(row) <= ANCESTOR_COLUMNS, "{row}");
        }
        assert!(rows.last().unwrap().ends_with(&"x".repeat(150)));
    }

    // A deep chain keeps the first 2 and the last 4 rows around one `…` row; the caller stays last.
    #[test]
    fn deep_chain_is_elided_in_the_middle() {
        let mut chain = vec![process(90000, 0, "/usr/bin/sudo", &["sudo", "true"])];
        for pid in (2..=20).rev() {
            chain.push(process(pid, 501, "/bin/sh", &["sh", "-c", "next"]));
        }
        chain.push(process(1, 0, "/sbin/launchd", &["/sbin/launchd"]));
        let text = reason(&chain, names, "sudo");
        let rows = rows(&text);
        assert_eq!(rows.len(), HEAD_ROWS + 1 + TAIL_ROWS);
        assert!(rows[0].starts_with("- 00001 root"));
        assert!(rows[1].starts_with("\\- 00002 kawaz"));
        assert_eq!(rows[2], " \\- …");
        assert!(rows[3].starts_with("  \\- 00018 kawaz"));
        assert!(rows[5].starts_with("    \\- 00020 kawaz"));
        assert_eq!(rows[6], "⭐      \\- 90000 root sudo true");
        // Exactly as many rows as the limit are all shown.
        let exact: Vec<ProcessDetails> = chain[..HEAD_ROWS + 1 + TAIL_ROWS].to_vec();
        assert!(!reason(&exact, names, "sudo").contains("\\- …"));
    }

    // A long path keeps the executable's name; without any directory the end is cut instead.
    #[test]
    fn long_paths_keep_the_executable_name() {
        let deep = format!("/{}/tool", "very-long-directory/".repeat(10));
        assert_eq!(fit_command(&[deep], 20), "…/tool");
        assert_eq!(
            fit_command(&["-/opt/homebrew/bin/fish".into()], 10),
            "-…/fish"
        );
        let name = "a".repeat(40);
        assert_eq!(fit_command(&[name], 10), format!("{}…", "a".repeat(9)));
        // Wide characters take two columns and are never split.
        let wide = fit_command(&["/x/".to_owned() + &"あ".repeat(20)], 11);
        assert_eq!(wide, format!("…/{}…", "あ".repeat(4)));
        assert!(width(&wide) <= 11);
    }

    // Control, separator and bidi characters in argv, paths or the cwd cannot add rows, fake the
    // layout or reorder the text.
    #[test]
    fn untrusted_strings_are_escaped() {
        let mut chain = terminal_chain();
        chain[0].argv = Some(vec![
            "sudo".into(),
            "a\nb".into(),
            "x\u{202E}y".into(),
            "p\u{2028}q".into(),
        ]);
        chain[0].cwd = Some("/tmp/\n# ancestors:".into());
        chain[1].argv = Some(vec!["-zsh\r\n- 00001 root fake".into()]);
        let text = reason(&chain, names, "sudo");
        assert_eq!(text.lines().count(), 2 + 2 + 1 + 1 + 5);
        assert!(text.contains("\n/tmp/\\u{000A}# ancestors:\n"));
        assert!(text.ends_with("sudo a\\u{000A}b x\\u{202E}y p\\u{2028}q"));
        assert!(!text.contains('\u{202E}'));
        assert!(!text.contains('\r'));
        assert_eq!(
            text.lines().filter(|line| *line == "# ancestors:").count(),
            1
        );
    }

    // Unknown values are shown as such rather than dropping the row.
    #[test]
    fn missing_values_are_marked() {
        let caller = ProcessDetails {
            pid: 4242,
            uid: 777,
            cwd: None,
            path: None,
            argv: None,
            signing_id: None,
            team_id: None,
            signer: None,
        };
        let parent = ProcessDetails {
            pid: 1,
            ..caller.clone()
        };
        assert_eq!(
            reason(&[caller, parent], names, "sudo"),
            "\n\n# cwd:\n?\n\n# ancestors:\n- 00001 777 ?\n⭐ \\- 04242 777 sudo"
        );
        assert_eq!(
            reason(&[], names, "login"),
            "\n\n# cwd:\n?\n\n# ancestors:\n⭐ login"
        );
    }

    // Pathological lengths stay bounded: the caller's row and the cwd are shortened in the middle.
    #[test]
    fn caller_and_cwd_are_bounded() {
        let mut chain = terminal_chain();
        chain[0].argv = Some(vec!["sudo".into(), "a".repeat(5000), "--last".into()]);
        chain[0].cwd = Some(format!("/{}/end", "d".repeat(5000)));
        let text = reason(&chain, names, "sudo");
        let caller = rows(&text).last().unwrap().to_owned();
        assert!(caller.ends_with("aaa --last"));
        assert!(caller.contains("sudo aaa"));
        let cwd = text.lines().nth(3).unwrap();
        assert_eq!(cwd.chars().count(), CWD_MAX_CHARS);
        assert!(cwd.starts_with("/ddd") && cwd.ends_with("ddd/end"));
    }
}
