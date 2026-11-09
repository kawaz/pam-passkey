//! The Touch ID dialog's text (`localizedReason`, DR-0004 ダイアログの本文), built from the
//! process chain the PAM module collected. Shared by the module, which shows it, and by
//! `_probe-dialog`, which shows the same text for a chain given to it.
//!
//! The OS puts its own lead-in (「<プロセス名> で次の操作を実行しようとしています:」) before the
//! text and wraps it in a text box about 26.6 widths of the digit `0` wide (proportional font),
//! growing the dialog downwards. Every string from the chain (argv, paths, user names) is
//! untrusted.

use std::path::Path;

use crate::ProcessDetails;

/// Width of a process tree row, in hundredths of the digit `0`'s width. Rows within it stay on
/// one line of the dialog.
pub const ROW_BUDGET: u32 = 2600;
/// A process tree of more rows shows its first `HEAD_ROWS` and last `TAIL_ROWS` rows around one
/// `…` row.
pub const MAX_ROWS: usize = 12;
pub const HEAD_ROWS: usize = 3;
pub const TAIL_ROWS: usize = 8;
/// The command is shown whole up to this many characters (the dialog's own limits on a very
/// long text are unobserved), then shortened in the middle.
pub const COMMAND_MAX_CHARS: usize = 400;
/// The working directory is shortened in the middle beyond this many characters.
pub const CWD_MAX_CHARS: usize = 200;
/// Programs that run a script given as their first argument; their rows keep the script's name.
const INTERPRETERS: &[&str] = &[
    "bun", "deno", "node", "python", "python3", "ruby", "perl", "php", "sh", "bash", "zsh", "fish",
    "dash", "ksh",
];
/// Inserted after `/` so that a path breaks at its directory boundaries.
const BREAK: char = '\u{200B}';
/// Inserted after `-` so that a path never breaks after a hyphen.
const NO_BREAK: char = '\u{2060}';

/// The dialog text: an empty line after the OS lead-in, then the caller's command, its working
/// directory and the process tree from launchd down to the caller. `processes` is the chain as
/// collected (caller first); `user_name` names a uid; `fallback` names the caller when the chain
/// is empty; `home` is shortened to `~` in the working directory.
pub fn reason(
    processes: &[ProcessDetails],
    user_name: impl Fn(u32) -> Option<String>,
    fallback: &str,
    home: &Path,
    japanese: bool,
) -> String {
    let (command_title, cwd_title, tree_title) = if japanese {
        ("実行コマンド:", "作業ディレクトリ:", "プロセスツリー:")
    } else {
        ("Command:", "Working directory:", "Process tree:")
    };
    let caller = processes.first();
    let command = caller
        .and_then(command_of)
        .map(|argv| escape(&argv.join(" ")))
        .unwrap_or_else(|| escape(fallback));
    let command = wrap_command(&shorten_middle(&command, COMMAND_MAX_CHARS));
    let cwd = caller
        .and_then(|caller| caller.cwd.as_deref())
        .map(|cwd| wrap_path(&shorten_middle(&escape(&tilde(cwd, home)), CWD_MAX_CHARS)))
        .unwrap_or_else(|| "?".to_owned());
    format!(
        "\n\n{command_title}\n{command}\n\n{cwd_title}\n{cwd}\n\n{tree_title}\n{}",
        tree_rows(processes, &user_name).join("\n")
    )
}

/// One row per process from launchd down to the caller, `<pid, 5 digits> <user> <body>`.
fn tree_rows(
    processes: &[ProcessDetails],
    user_name: &impl Fn(u32) -> Option<String>,
) -> Vec<String> {
    if processes.is_empty() {
        return vec!["?".to_owned()];
    }
    let tree: Vec<&ProcessDetails> = processes.iter().rev().collect();
    let shown: Vec<Option<&ProcessDetails>> = if tree.len() > MAX_ROWS {
        tree[..HEAD_ROWS]
            .iter()
            .map(|process| Some(*process))
            .chain(std::iter::once(None))
            .chain(
                tree[tree.len() - TAIL_ROWS..]
                    .iter()
                    .map(|process| Some(*process)),
            )
            .collect()
    } else {
        tree.into_iter().map(Some).collect()
    };
    shown
        .into_iter()
        .map(|process| match process {
            None => "…".to_owned(),
            Some(process) => {
                let user = user_name(process.uid).unwrap_or_else(|| process.uid.to_string());
                let head = format!("{:05} {} ", process.pid, escape(&user));
                let budget = ROW_BUDGET.saturating_sub(width(&head));
                let body = command_of(process)
                    .map(|argv| fit_body(&argv, budget))
                    .unwrap_or_else(|| "?".to_owned());
                format!("{head}{body}")
            }
        })
        .collect()
}

/// argv when known, otherwise the executable path alone.
fn command_of(process: &ProcessDetails) -> Option<Vec<String>> {
    process
        .argv
        .clone()
        .filter(|argv| argv.first().is_some_and(|first| !first.is_empty()))
        .or_else(|| process.path.clone().map(|path| vec![path]))
}

/// A row's body within `budget`: argv whole, else the program's short name with the rest of
/// argv, else that cut at the end.
fn fit_body(argv: &[String], budget: u32) -> String {
    let argv: Vec<String> = argv.iter().map(|arg| escape(arg)).collect();
    let whole = argv.join(" ");
    if width(&whole) <= budget {
        return whole;
    }
    let short = short_argv(&argv).join(" ");
    if width(&short) <= budget {
        return short;
    }
    cut_end(&short, budget)
}

/// argv with argv[0] as its app's name (`Ghostty.app`) or its base name (`-zsh` for `-/bin/zsh`);
/// an interpreter's script keeps only its base name (`bun index.ts …`).
fn short_argv(argv: &[String]) -> Vec<String> {
    let (program, rest) = argv.split_first().expect("argv has argv[0]");
    if let Some(app) = app_name(program) {
        return std::iter::once(app.to_owned())
            .chain(rest.iter().cloned())
            .collect();
    }
    let name = base_name(program);
    let rest: Vec<String> = match rest.split_first() {
        Some((script, rest))
            if INTERPRETERS.contains(&name.trim_start_matches('-'))
                && script.contains('/')
                && !script.starts_with('-') =>
        {
            std::iter::once(base_name(script))
                .chain(rest.iter().cloned())
                .collect()
        }
        _ => rest.to_vec(),
    };
    std::iter::once(name).chain(rest).collect()
}

/// `Ghostty.app` for `…/Ghostty.app/Contents/MacOS/ghostty`.
fn app_name(program: &str) -> Option<&str> {
    let parts: Vec<&str> = program.rsplitn(4, '/').collect();
    match parts.as_slice() {
        [executable, "MacOS", "Contents", bundle_path] if !executable.is_empty() => {
            let bundle = bundle_path.rsplit('/').next().unwrap_or(bundle_path);
            (bundle.len() > ".app".len() && bundle.ends_with(".app")).then_some(bundle)
        }
        _ => None,
    }
}

/// The last path component, keeping a login shell's leading `-`; the whole when it has none.
fn base_name(program: &str) -> String {
    let (dash, path) = match program.strip_prefix('-') {
        Some(path) => ("-", path),
        None => ("", program),
    };
    match path.rsplit('/').next() {
        Some(name) if !name.is_empty() => format!("{dash}{name}"),
        _ => program.to_owned(),
    }
}

/// The start of `text` that fits `budget` with a trailing `…`.
fn cut_end(text: &str, budget: u32) -> String {
    let mut kept = String::new();
    let mut used = 0;
    for ch in text.chars() {
        if used + unit(ch) + unit('…') > budget {
            break;
        }
        kept.push(ch);
        used += unit(ch);
    }
    let mut kept = kept.trim_end().to_owned();
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

/// `home` and what is under it as `~`.
fn tilde(path: &str, home: &Path) -> String {
    let Some(home) = home.to_str().map(|home| home.trim_end_matches('/')) else {
        return path.to_owned();
    };
    if home.is_empty() {
        return path.to_owned();
    }
    match path.strip_prefix(home) {
        Some("") => "~".to_owned(),
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_owned(),
    }
}

/// A path that breaks only at directory boundaries: a break opportunity after each `/`, none
/// after a `-`.
fn wrap_path(path: &str) -> String {
    let mut wrapped = String::with_capacity(path.len());
    for ch in path.chars() {
        wrapped.push(ch);
        match ch {
            '/' => wrapped.push(BREAK),
            '-' => wrapped.push(NO_BREAK),
            _ => {}
        }
    }
    wrapped
}

/// The command with its words that hold a `/` wrapped as paths.
fn wrap_command(command: &str) -> String {
    command
        .split(' ')
        .map(|word| {
            if word.contains('/') {
                wrap_path(word)
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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

/// Control characters, the line and paragraph separators and format characters as `\u{XXXX}`,
/// so that no string from the chain can break a row, fake the layout, reorder what is shown or
/// pass for the break controls the text inserts itself.
fn escape(text: &str) -> String {
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

/// Approximate width of a character in the dialog's font, in hundredths of the digit `0`'s
/// width. Upper bounds per class, measured against the real dialog.
fn unit(ch: char) -> u32 {
    match ch {
        ' ' | '.' | ',' | ':' | ';' | '\'' | '!' | '|' | 'i' | 'j' | 'l' => 50,
        '/' | '(' | ')' | '[' | ']' | '{' | '}' | 'f' | 'r' | 't' | 'I' => 65,
        'm' | 'w' | 'M' | 'W' | '@' | '%' => 155,
        'A'..='Z' | '&' => 125,
        ' '..='~' => 105,
        '\u{2B50}' | '\u{1F000}'..=char::MAX => 200,
        _ => 160,
    }
}

fn width(text: &str) -> u32 {
    text.chars().map(unit).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/Users/kawaz";

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

    fn text(chain: &[ProcessDetails], japanese: bool) -> String {
        reason(chain, names, "sudo", Path::new(HOME), japanese)
    }

    /// The chain of a sudo typed in a terminal, caller first as the module collects it.
    fn terminal_chain() -> Vec<ProcessDetails> {
        vec![
            process(57111, 0, "/usr/bin/sudo", &["sudo", "-k", "true"]),
            process(8991, 501, "/bin/zsh", &["-/bin/zsh"]),
            process(
                8990,
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

    fn tree(text: &str) -> Vec<&str> {
        let (_, tree) = text
            .split_once("プロセスツリー:\n")
            .or_else(|| text.split_once("Process tree:\n"))
            .unwrap();
        tree.lines().collect()
    }

    // Its own paragraph after the OS lead-in: the command, the working directory under `~`, and
    // the tree from launchd down to the caller, one row per process.
    #[test]
    fn terminal_sudo_shows_command_cwd_and_tree() {
        assert_eq!(
            text(&terminal_chain(), true),
            "\n\n実行コマンド:\nsudo -k true\n\n作業ディレクトリ:\n~/\u{200B}work\n\n\
             プロセスツリー:\n\
             00001 root /sbin/launchd\n\
             07734 kawaz Ghostty.app\n\
             08990 root login -flp kawaz…\n\
             08991 kawaz -/bin/zsh\n\
             57111 root sudo -k true"
        );
    }

    // The headings follow the user's language; the rest is the same.
    #[test]
    fn headings_follow_the_language() {
        let english = text(&terminal_chain(), false);
        assert!(english.starts_with("\n\nCommand:\nsudo -k true\n\nWorking directory:\n~/"));
        assert!(english.contains("\n\nProcess tree:\n00001 root /sbin/launchd\n"));
        assert_eq!(tree(&english), tree(&text(&terminal_chain(), true)));
    }

    // Only the home itself and paths under it become `~`.
    #[test]
    fn home_is_shortened_to_tilde() {
        let home = Path::new(HOME);
        assert_eq!(tilde("/Users/kawaz", home), "~");
        assert_eq!(tilde("/Users/kawaz/a/b", home), "~/a/b");
        assert_eq!(tilde("/Users/kawazz/a", home), "/Users/kawazz/a");
        assert_eq!(tilde("/private/tmp", home), "/private/tmp");
        assert_eq!(tilde("/Users/kawaz/a", Path::new("/Users/kawaz/")), "~/a");
        assert_eq!(tilde("/a", Path::new("/")), "/a");
    }

    // Paths break after `/` and never after `-`; words without `/` keep the font's own breaks.
    #[test]
    fn paths_break_at_directory_boundaries() {
        let mut chain = terminal_chain();
        chain[0].argv = Some(vec![
            "sudo".into(),
            "install".into(),
            "-m".into(),
            "target/release/libpam_passkey.dylib".into(),
            "/usr/local/lib/pam/pam-passkey.so".into(),
        ]);
        chain[0].cwd = Some("/Users/kawaz/repos/pam-passkey/main".into());
        let text = text(&chain, true);
        assert!(text.contains(
            "\nsudo install -m target/\u{200B}release/\u{200B}libpam_passkey.dylib \
             /\u{200B}usr/\u{200B}local/\u{200B}lib/\u{200B}pam/\u{200B}pam-\u{2060}passkey.so\n"
        ));
        assert!(text.contains("\n~/\u{200B}repos/\u{200B}pam-\u{2060}passkey/\u{200B}main\n"));
        // The tree never carries them.
        for row in tree(&text) {
            assert!(!row.contains(BREAK) && !row.contains(NO_BREAK), "{row}");
        }
    }

    // Every row of the tree, the caller's included, fits one line of the dialog.
    #[test]
    fn tree_rows_fit_the_budget() {
        let mut chain = terminal_chain();
        chain[0].argv = Some(vec!["sudo".into(), "x".repeat(150)]);
        chain[1].argv = Some(vec!["-/bin/zsh".into(), "あ".repeat(30)]);
        chain[2].argv = Some(vec!["/bin/x".into(), "🟢".repeat(30)]);
        let text = text(&chain, true);
        for row in tree(&text) {
            assert!(width(row) <= ROW_BUDGET, "{row}");
        }
        assert_eq!(
            tree(&text)[4],
            format!("57111 root sudo {}…", "x".repeat(9))
        );
    }

    // A body shrinks in order: argv whole, the app's name, argv[0]'s base name (a script keeps its
    // name after an interpreter), then the end is cut (no space before the `…`).
    #[test]
    fn bodies_shrink_in_order() {
        let argv = |args: &[&str]| args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        assert_eq!(fit_body(&argv(&["/sbin/launchd"]), 1650), "/sbin/launchd");
        assert_eq!(
            fit_body(
                &argv(&["/Applications/Ghostty.app/Contents/MacOS/ghostty", "-e"]),
                1650
            ),
            "Ghostty.app -e"
        );
        assert_eq!(
            fit_body(&argv(&["/usr/libexec/xpcproxy", "x"]), 1000),
            "xpcproxy x"
        );
        assert_eq!(
            fit_body(
                &argv(&[
                    "/nix/store/r3r9-bun-1.4.2/bin/bun",
                    "/Users/kawaz/.claude/plugins/cli/src/index.ts",
                    "daemon",
                    "run",
                ]),
                2200
            ),
            "bun index.ts daemon run"
        );
        // A first argument that is an option, or one without `/`, is no script.
        assert_eq!(
            fit_body(&argv(&["/bin/zsh", "-c", "source /a/b/c/d/e/f/g/h"]), 1650),
            "zsh -c source /a…"
        );
        assert_eq!(fit_body(&argv(&["/bin/sh", "-x/y", "z"]), 800), "sh -x/y z");
        assert_eq!(fit_body(&argv(&["-/bin/zsh", "--login"]), 700), "-zsh…");
        // Nothing but the `…` fits.
        assert_eq!(fit_body(&argv(&["abcdef"]), 100), "…");
        assert_eq!(app_name("/Applications/.app/Contents/MacOS/x"), None);
        assert_eq!(
            app_name("Ghostty.app/Contents/MacOS/ghostty"),
            Some("Ghostty.app")
        );
        assert_eq!(app_name("/A.app/Contents/MacOS/"), None);
        assert_eq!(base_name("/usr/bin/"), "/usr/bin/");
    }

    // Widths follow the per-class table, in hundredths of the digit `0`.
    #[test]
    fn widths_follow_the_table() {
        assert_eq!(width("0123456789"), 1050);
        assert_eq!(width(" .,:;'!|ijl"), 550);
        assert_eq!(width("/()[]{}frtI"), 715);
        assert_eq!(width("mwMW@%"), 930);
        assert_eq!(width("AZ&"), 375);
        assert_eq!(width("ab~"), 315);
        assert_eq!(width("🟢⭐"), 400);
        assert_eq!(width("あ漢…"), 480);
    }

    // More than 12 rows keep the first 3 and the last 8 around one `…` row; the caller is last.
    #[test]
    fn deep_tree_is_elided_in_the_middle() {
        let mut chain = vec![process(90000, 0, "/usr/bin/sudo", &["sudo", "true"])];
        for pid in (2..=20).rev() {
            chain.push(process(pid, 501, "/bin/sh", &["sh", "-c", "next"]));
        }
        chain.push(process(1, 0, "/sbin/launchd", &["/sbin/launchd"]));
        let text = text(&chain, true);
        let rows = tree(&text);
        assert_eq!(rows.len(), MAX_ROWS);
        assert!(rows[0].starts_with("00001 root"));
        assert!(rows[2].starts_with("00003 kawaz"));
        assert_eq!(rows[3], "…");
        assert!(rows[4].starts_with("00014 kawaz"));
        assert!(rows[10].starts_with("00020 kawaz"));
        assert_eq!(rows[11], "90000 root sudo true");
        // Exactly as many rows as the limit are all shown.
        let exact: Vec<ProcessDetails> = chain[..MAX_ROWS].to_vec();
        let text = super::reason(&exact, names, "sudo", Path::new(HOME), true);
        assert_eq!(tree(&text).len(), MAX_ROWS);
        assert!(!tree(&text).contains(&"…"));
    }

    // Control, separator, bidi and format characters cannot add rows, fake the layout, reorder
    // the text or pass for the break controls the text inserts.
    #[test]
    fn untrusted_strings_are_escaped() {
        let mut chain = terminal_chain();
        chain[0].argv = Some(vec![
            "sudo".into(),
            "a\nb".into(),
            "x\u{202E}y".into(),
            "p\u{2028}q".into(),
            "z\u{200B}w\u{2060}v\u{00AD}u\u{E0041}t".into(),
        ]);
        chain[0].cwd = Some("/tmp/\n\nプロセスツリー:".into());
        chain[1].argv = Some(vec!["-zsh\r\n00001 root fake".into()]);
        let text = text(&chain, true);
        assert_eq!(text.lines().count(), 4 + 3 + 2 + 5);
        assert!(text.contains("\nsudo a\\u{000A}b x\\u{202E}y p\\u{2028}q "));
        assert!(text.contains("z\\u{200B}w\\u{2060}v\\u{00AD}u\\u{E0041}t\n"));
        assert!(text.contains("\n/\u{200B}tmp/\u{200B}\\u{000A}\\u{000A}プロセスツリー:\n"));
        assert!(text.contains("\n08991 kawaz -zsh\\u{000D}…\n"));
        assert!(!text.contains('\u{202E}') && !text.contains('\r') && !text.contains('\u{00AD}'));
        // The only ZWSP left are those inserted after `/`; no WJ at all.
        assert_eq!(text.matches(BREAK).count(), 2);
        assert_eq!(text.matches("/\u{200B}").count(), 2);
        assert!(!text.contains(NO_BREAK));
        assert_eq!(
            text.lines()
                .filter(|line| *line == "プロセスツリー:")
                .count(),
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
            text(&[caller, parent], true),
            "\n\n実行コマンド:\nsudo\n\n作業ディレクトリ:\n?\n\nプロセスツリー:\n00001 777 ?\n04242 777 ?"
        );
        assert_eq!(
            reason(&[], names, "login", Path::new(HOME), false),
            "\n\nCommand:\nlogin\n\nWorking directory:\n?\n\nProcess tree:\n?"
        );
    }

    // Pathological lengths stay bounded: the command and the cwd are shortened in the middle.
    #[test]
    fn command_and_cwd_are_bounded() {
        let mut chain = terminal_chain();
        chain[0].argv = Some(vec!["sudo".into(), "a".repeat(5000), "--last".into()]);
        chain[0].cwd = Some(format!("/{}/end", "d".repeat(5000)));
        let text = text(&chain, true);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[3].chars().count(), COMMAND_MAX_CHARS);
        assert!(lines[3].starts_with("sudo aaa") && lines[3].ends_with("aaa --last"));
        let cwd = lines[6].replace(BREAK, "");
        assert_eq!(cwd.chars().count(), CWD_MAX_CHARS);
        assert!(cwd.starts_with("/ddd") && cwd.ends_with("ddd/end"));
    }
}
