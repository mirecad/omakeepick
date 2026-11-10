//! KeePass auto-type sequences and typing them with `wtype`.
//!
//! Supported syntax (a KeePass / KeePassXC subset):
//! * field placeholders `{USERNAME}` `{PASSWORD}` `{TITLE}` `{URL}` `{NOTES}` `{TOTP}` `{S:Name}`
//! * keys `{TAB}` `{ENTER}` `{SPACE}` `{BS}` `{DEL}` `{UP}` … `{F1}`–`{F16}`, with an optional
//!   repeat count (`{TAB 2}`), and `~` for Enter
//! * modifiers `+` (Shift), `^` (Ctrl), `%` (Alt) applied to the next key or character
//! * `{DELAY 500}` (pause) and `{DELAY=20}` (set the per-keystroke delay)
//! * `{CLEARFIELD}` (Ctrl+A, Backspace), and literal escapes `{+}` `{^}` `{%}` `{~}` `{{}` `{}}`
//!   `{(}` `{)}` `{[}` `{]}`
//!
//! Field values (passwords, usernames, TOTP codes…) go to `wtype -` on stdin; they never
//! appear on a command line. Only key names and the literal characters of chords like `^a`
//! are passed as arguments.
//!
//! A value is in this code's hands only while it is being typed. A placeholder stays a name
//! until its turn comes; then the value is taken from the database, given to `wtype` a short
//! burst at a time, and dropped. So a pause, the wait before typing starts and the key presses
//! in between hold no secret. Dropping the future that types, which is what a lock does, wipes
//! the value; what is left is the burst `wtype` already has, which it types to the end.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use zeroize::Zeroizing;

use crate::clipboard::Clipboard;
use crate::inflight::Tracker;
use crate::tool::{Stop, Tool};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Modifier {
    Shift,
    Ctrl,
    Alt,
}

impl Modifier {
    fn wtype_name(self) -> &'static str {
        match self {
            Modifier::Shift => "shift",
            Modifier::Ctrl => "ctrl",
            Modifier::Alt => "alt",
        }
    }
}

// Debug only in tests: `Text` is part of the database.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Token {
    /// Literal text of the sequence.
    Text(Zeroizing<String>),
    /// A field placeholder, by the name [`Fields`] knows it under. Its value is looked up when
    /// its turn comes, not before.
    Field(String),
    /// An xkb keysym name, pressed `repeat` times with `mods` held.
    Key {
        name: &'static str,
        mods: Vec<Modifier>,
        repeat: u32,
    },
    /// A literal character of the sequence typed with modifiers held (`^a`). Never part of a
    /// field: a modifier before a field placeholder is rejected.
    Chord {
        text: char,
        mods: Vec<Modifier>,
    },
    Delay(u64),
    SetKeyDelay(u64),
}

/// Resolves field placeholders (`USERNAME`, `S:Name`, `TOTP`, …) to their values. `None` is a
/// field the entry does not have, which types nothing.
pub trait Fields {
    fn field(&self, name: &str) -> Result<Option<Zeroizing<String>>, String>;
}

fn key_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "TAB" => "Tab",
        "ENTER" => "Return",
        "SPACE" => "space",
        "BS" | "BKSP" | "BACKSPACE" => "BackSpace",
        "DEL" | "DELETE" => "Delete",
        "INS" | "INSERT" => "Insert",
        "UP" => "Up",
        "DOWN" => "Down",
        "LEFT" => "Left",
        "RIGHT" => "Right",
        "HOME" => "Home",
        "END" => "End",
        "PGUP" => "Prior",
        "PGDN" => "Next",
        "ESC" => "Escape",
        "CAPSLOCK" => "Caps_Lock",
        "NUMLOCK" => "Num_Lock",
        "SCROLLLOCK" => "Scroll_Lock",
        "PRTSC" => "Print",
        "BREAK" => "Break",
        "APPS" => "Menu",
        "ADD" => "KP_Add",
        "SUBTRACT" => "KP_Subtract",
        "MULTIPLY" => "KP_Multiply",
        "DIVIDE" => "KP_Divide",
        "F1" => "F1",
        "F2" => "F2",
        "F3" => "F3",
        "F4" => "F4",
        "F5" => "F5",
        "F6" => "F6",
        "F7" => "F7",
        "F8" => "F8",
        "F9" => "F9",
        "F10" => "F10",
        "F11" => "F11",
        "F12" => "F12",
        "F13" => "F13",
        "F14" => "F14",
        "F15" => "F15",
        "F16" => "F16",
        "NUMPAD0" => "KP_0",
        "NUMPAD1" => "KP_1",
        "NUMPAD2" => "KP_2",
        "NUMPAD3" => "KP_3",
        "NUMPAD4" => "KP_4",
        "NUMPAD5" => "KP_5",
        "NUMPAD6" => "KP_6",
        "NUMPAD7" => "KP_7",
        "NUMPAD8" => "KP_8",
        "NUMPAD9" => "KP_9",
        _ => return None,
    })
}

struct Builder {
    tokens: Vec<Token>,
    mods: Vec<Modifier>,
    /// Whether the last token is literal sequence text, which further literals may join.
    last_literal: bool,
}

impl Builder {
    /// Literal text from the sequence itself. Adjacent literals share one token.
    fn text(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        let mut chars = s.chars();
        if !self.mods.is_empty() {
            let first = chars.next().expect("non-empty");
            self.tokens.push(Token::Chord { text: first, mods: std::mem::take(&mut self.mods) });
        }
        let rest = chars.as_str();
        if rest.is_empty() {
            return;
        }
        if self.last_literal
            && let Some(Token::Text(prev)) = self.tokens.last_mut()
        {
            prev.push_str(rest);
            return;
        }
        self.tokens.push(Token::Text(Zeroizing::new(rest.to_string())));
        self.last_literal = true;
    }

    fn field(&mut self, name: String) {
        self.tokens.push(Token::Field(name));
        self.last_literal = false;
    }

    fn key(&mut self, name: &'static str, repeat: u32) {
        let mods = std::mem::take(&mut self.mods);
        self.tokens.push(Token::Key { name, mods, repeat });
        self.last_literal = false;
    }

    fn plain(&mut self, token: Token) {
        self.mods.clear();
        self.tokens.push(token);
        self.last_literal = false;
    }
}

/// Longest sequence accepted. Sequences can come from the database, so from a sync peer.
const MAX_SEQUENCE_LEN: usize = 4096;

/// Parses a sequence. No field is looked at here: placeholders become [`Token::Field`].
pub fn parse(sequence: &str) -> Result<Vec<Token>, String> {
    if sequence.len() > MAX_SEQUENCE_LEN {
        return Err("The auto-type sequence is too long".into());
    }
    let mut b = Builder { tokens: Vec::new(), mods: Vec::new(), last_literal: false };
    let mut chars = sequence.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '+' => b.mods.push(Modifier::Shift),
            '^' => b.mods.push(Modifier::Ctrl),
            // Alt (and the Super keys, which key_name no longer knows) could move focus to
            // another window before the password is typed: %{TAB}{PASSWORD}. A sequence from a
            // shared database must not be able to do that.
            '%' => return Err("Alt is not supported in auto-type sequences".into()),
            '~' => b.key("Return", 1),
            '{' => {
                // `{}}` is the literal `}`; otherwise read up to the closing brace.
                let mut inner = String::new();
                if chars.peek() == Some(&'}') {
                    chars.next();
                    if chars.peek() == Some(&'}') {
                        chars.next();
                        b.text("}");
                        continue;
                    }
                    return Err("Empty placeholder {} in auto-type sequence".into());
                }
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(ch) => inner.push(ch),
                        None => return Err("Unclosed placeholder in auto-type sequence".into()),
                    }
                }
                placeholder(&mut b, &inner)?;
            }
            other => b.text(other.encode_utf8(&mut [0; 4])),
        }
    }
    Ok(b.tokens)
}

// Errors never quote the sequence: it is part of the database, and the message ends up in a
// desktop notification.
fn placeholder(b: &mut Builder, inner: &str) -> Result<(), String> {
    if matches!(inner, "+" | "^" | "%" | "~" | "{" | "(" | ")" | "[" | "]") {
        b.text(inner);
        return Ok(());
    }
    let upper = inner.to_uppercase();
    if let Some(ms) = upper.strip_prefix("DELAY=") {
        let ms = ms.trim().parse().map_err(|_| "Invalid {DELAY=…} in auto-type sequence".to_string())?;
        b.plain(Token::SetKeyDelay(ms));
        return Ok(());
    }
    if let Some(ms) = upper.strip_prefix("DELAY ") {
        let ms = ms.trim().parse().map_err(|_| "Invalid {DELAY …} in auto-type sequence".to_string())?;
        b.plain(Token::Delay(ms));
        return Ok(());
    }
    if upper == "CLEARFIELD" {
        b.mods.clear();
        b.key("a", 1);
        if let Some(Token::Key { mods, .. }) = b.tokens.last_mut() {
            mods.push(Modifier::Ctrl);
        }
        b.key("BackSpace", 1);
        return Ok(());
    }
    let (name, repeat) = match upper.rsplit_once(' ') {
        Some((name, count)) if count.chars().all(|c| c.is_ascii_digit()) => (
            name.to_string(),
            count.parse::<u32>().map_err(|_| "Invalid key repeat in auto-type sequence".to_string())?,
        ),
        _ => (upper.clone(), 1),
    };
    if let Some(key) = key_name(&name) {
        b.key(key, repeat.min(100));
        return Ok(());
    }
    // Fields keep their original case for `{S:Custom Name}`.
    let field_name = match upper.as_str() {
        "USERNAME" | "PASSWORD" | "TITLE" | "URL" | "NOTES" | "TOTP" => upper.clone(),
        _ if upper.starts_with("S:") => format!("S:{}", &inner[2..]),
        _ => return Err("Unsupported placeholder in auto-type sequence".into()),
    };
    // A modifier would turn the field's first character into a chord, and chords are typed
    // with the character as a wtype argument, readable by other users. wtype drops keys sent on
    // stdin while a modifier is held, so there is no safe way to type it.
    if !b.mods.is_empty() {
        return Err("Modifiers before a field are not supported in auto-type sequences".into());
    }
    b.field(field_name);
    Ok(())
}

/// Sends tokens to the focused window.
#[allow(async_fn_in_trait)] // only used with concrete types on one thread
pub trait Typist {
    /// How many characters to hand to [`text`](Self::text) at a time.
    fn burst(&self, key_delay: u64) -> usize;
    async fn text(&mut self, text: &str, key_delay: u64) -> Result<(), String>;
    async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String>;
    async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String>;
}

/// What an action cut short by a lock fails with.
pub const CANCELLED: &str = "cancelled";

/// The most text a typist is handed at a time.
const MAX_BURST_CHARS: usize = 64;
const MAX_TYPED_CHARS: usize = 8192;

/// Splits `text` on character boundaries into pieces of at most `n` characters.
fn chunks(text: &str, n: usize) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let end = rest.char_indices().nth(n).map_or(rest.len(), |(i, _)| i);
        let (head, tail) = rest.split_at(end);
        rest = tail;
        Some(head)
    })
}

/// Types `tokens`. A field's value is asked of `fields` when its turn comes and dropped as soon
/// as it is typed.
///
/// Stopping it is dropping it, and that is safe at any point: the value in hand is wiped with
/// the future, and what a typist has started ends on its own or is ended (see [`Tool`]).
pub async fn run(
    tokens: &[Token],
    fields: &impl Fields,
    typist: &mut impl Typist,
    key_delay: u64,
) -> Result<(), String> {
    let mut delay = key_delay;
    let mut typed = 0usize;
    for token in tokens {
        match token {
            Token::Text(text) => type_text(text, typist, delay, &mut typed).await?,
            Token::Field(name) => {
                if let Some(value) = fields.field(name)? {
                    type_text(&value, typist, delay, &mut typed).await?;
                }
            }
            Token::Key { name, mods, repeat } => typist.key(name, mods, *repeat).await?,
            Token::Chord { text, mods } => typist.chord(*text, mods).await?,
            Token::Delay(ms) => tokio::time::sleep(Duration::from_millis((*ms).min(10_000))).await,
            Token::SetKeyDelay(ms) => delay = (*ms).min(1000),
        }
    }
    Ok(())
}

/// In bursts, each of them one `wtype` or one paste, and with a ceiling: a sequence from the
/// database could ask for a megabyte.
async fn type_text(
    text: &str,
    typist: &mut impl Typist,
    key_delay: u64,
    typed: &mut usize,
) -> Result<(), String> {
    for burst in chunks(text, typist.burst(key_delay).clamp(1, MAX_BURST_CHARS)) {
        *typed += burst.chars().count();
        if *typed > MAX_TYPED_CHARS {
            return Err("The auto-type sequence types too much text".into());
        }
        typist.text(burst, key_delay).await?;
    }
    Ok(())
}

fn with_mods(mods: &[Modifier], inner: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut args = Vec::new();
    for m in mods {
        args.extend(["-M".to_string(), m.wtype_name().to_string()]);
    }
    args.extend(inner);
    for m in mods.iter().rev() {
        args.extend(["-m".to_string(), m.wtype_name().to_string()]);
    }
    args
}

/// What `wtype` needs for one key besides the delay it is asked for: a press and a release,
/// two milliseconds each.
const KEY_MILLIS: u64 = 4;

/// How long the text handed to one `wtype` may take to type. `wtype` reads all of its input
/// before it types any, so this is how long it goes on typing after a lock, and how long a
/// suspend waits for it.
const BURST_MILLIS: u64 = 500;

/// How much longer than its work should take a `wtype` may run once nobody waits for it.
const GRACE: Duration = Duration::from_millis(500);

/// How much longer than its work should take a `wtype` is waited for. One that has not ended
/// by then is waiting on the compositor, and whoever waits on it has a value in hand.
const PATIENCE: Duration = Duration::from_secs(5);

fn typing_time(keys: u64, key_delay: u64) -> Duration {
    Duration::from_millis(keys * (key_delay + KEY_MILLIS))
}

/// Types with the virtual-keyboard protocol. Works for native Wayland windows.
pub struct Wtype {
    inflight: Tracker,
}

impl Wtype {
    pub fn new(inflight: &Tracker) -> Wtype {
        Wtype { inflight: inflight.clone() }
    }

    /// Starts a `wtype` that has `work` to do. It is not killed while it does it: between a
    /// key press and its release, that would leave the key held down in the focused window.
    /// Left alone it ends by itself, and is killed only if it takes much longer than it should.
    fn start(&self, args: &[String], stdin: Stdio, work: Duration) -> Result<Tool, String> {
        let mut command = Command::new("wtype");
        command.args(args).stdin(stdin).stdout(Stdio::null()).stderr(Stdio::piped());
        Tool::spawn(command, Stop::Within(work + GRACE), None, &self.inflight).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "tool_missing:wtype is not installed".to_string(),
            _ => format!("Cannot run wtype: {e}"),
        })
    }

    /// Runs `wtype` with arguments only: modifier and key names, and the character of a chord.
    async fn press(&self, args: &[String], keys: u32) -> Result<(), String> {
        let work = typing_time(u64::from(keys), 0);
        finish(self.start(args, Stdio::null(), work)?, work).await
    }
}

/// Waits for a `wtype` that has `work` to do to end. A failure is reported with what it
/// printed.
async fn finish(mut tool: Tool, work: Duration) -> Result<(), String> {
    let mut stderr = tool.stderr();
    let mut message = Vec::new();
    let read = async {
        if let Some(stderr) = &mut stderr {
            let _ = stderr.read_to_end(&mut message).await;
        }
    };
    let ended = async { tokio::join!(tool.wait(), read).0 };
    let Ok(status) = tokio::time::timeout(work + PATIENCE, ended).await else {
        // Dropped here, it is given its grace and then killed.
        return Err("wtype did not finish".into());
    };
    if !status.map_err(|e| format!("wtype: {e}"))?.success() {
        return Err(format!("wtype failed: {}", String::from_utf8_lossy(&message).trim()));
    }
    // Give the compositor a moment between virtual keyboards so events stay in order.
    tokio::time::sleep(Duration::from_millis(12)).await;
    Ok(())
}

impl Typist for Wtype {
    fn burst(&self, key_delay: u64) -> usize {
        usize::try_from(BURST_MILLIS / (key_delay + KEY_MILLIS)).unwrap_or(1)
    }

    async fn text(&mut self, text: &str, key_delay: u64) -> Result<(), String> {
        let work = typing_time(text.chars().count() as u64, key_delay);
        // wtype refuses a delay of 0; without the option it does not wait between keys. The
        // `-` comes last: wtype types whatever follows it as text.
        let mut args = Vec::new();
        if key_delay > 0 {
            args.extend(["-d".to_string(), key_delay.to_string()]);
        }
        args.push("-".to_string());
        let mut tool = self.start(&args, Stdio::piped(), work)?;
        let mut stdin = tool.stdin().expect("piped stdin");
        let written = stdin.write_all(text.as_bytes()).await;
        drop(stdin);
        // A wtype that could not be written to has ended; `finish` says why.
        finish(tool, work).await?;
        written.map_err(|e| format!("wtype: {e}"))
    }

    async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String> {
        let keys = (0..repeat).flat_map(|_| ["-k".to_string(), name.to_string()]);
        self.press(&with_mods(mods, keys), repeat).await
    }

    async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String> {
        self.press(&with_mods(mods, ["--".to_string(), text.to_string()]), 1).await
    }
}

/// XWayland windows mis-handle wtype's per-character keymaps, so text is pasted instead: offered
/// (as sensitive) on both the clipboard and the primary selection, then Shift+Insert.
pub struct PasteTypist<'a> {
    clipboard: &'a Clipboard,
    keys: Wtype,
}

impl<'a> PasteTypist<'a> {
    pub fn new(clipboard: &'a Clipboard, inflight: &Tracker) -> PasteTypist<'a> {
        PasteTypist { clipboard, keys: Wtype::new(inflight) }
    }
}

impl Typist for PasteTypist<'_> {
    fn burst(&self, _key_delay: u64) -> usize {
        MAX_BURST_CHARS
    }

    async fn text(&mut self, text: &str, _key_delay: u64) -> Result<(), String> {
        // Each selection is held by a `wl-copy` of its own, which is killed when this returns
        // or is dropped: the piece is on the selections for this paste only.
        let _clipboard = self.clipboard.offer(text, false).await?;
        let _primary = self.clipboard.offer(text, true).await?;
        tokio::time::sleep(Duration::from_millis(60)).await;
        self.keys.key("Insert", &[Modifier::Shift], 1).await?;
        // The application reads the selection asynchronously.
        tokio::time::sleep(Duration::from_millis(250)).await;
        Ok(())
    }

    async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String> {
        self.keys.key(name, mods, repeat).await
    }

    async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String> {
        self.keys.chord(text, mods).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// What happened, in order: fields asked for and what the typist was told to do.
    #[derive(Default)]
    struct Log(RefCell<Vec<String>>);

    impl Log {
        fn take(&self) -> Vec<String> {
            self.0.take()
        }
    }

    struct Map<'a>(HashMap<&'static str, &'static str>, &'a Log);

    impl Fields for Map<'_> {
        fn field(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
            self.1.0.borrow_mut().push(format!("field({name})"));
            Ok(self.0.get(name).map(|v| Zeroizing::new(v.to_string())))
        }
    }

    fn fields(log: &Log) -> Map<'_> {
        Map(
            HashMap::from([
                ("USERNAME", "madev"),
                ("PASSWORD", "p@ss{}~+"),
                ("S:PIN", "4321"),
                ("TOTP", "123456"),
            ]),
            log,
        )
    }

    struct Recorder<'a>(&'a Log);

    impl Typist for Recorder<'_> {
        fn burst(&self, _key_delay: u64) -> usize {
            usize::MAX
        }
        async fn text(&mut self, text: &str, key_delay: u64) -> Result<(), String> {
            self.0.0.borrow_mut().push(format!("text({text},{key_delay})"));
            Ok(())
        }
        async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String> {
            self.0.0.borrow_mut().push(format!("key({name},{mods:?},{repeat})"));
            Ok(())
        }
        async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String> {
            self.0.0.borrow_mut().push(format!("chord({text},{mods:?})"));
            Ok(())
        }
    }

    /// Runs `sequence` and returns what was typed, without the lookups.
    async fn typed(sequence: &str) -> Vec<String> {
        let log = Log::default();
        run(&parse(sequence).unwrap(), &fields(&log), &mut Recorder(&log), 8).await.unwrap();
        log.take().into_iter().filter(|line| !line.starts_with("field(")).collect()
    }

    fn text(s: &str) -> Token {
        Token::Text(Zeroizing::new(s.into()))
    }

    fn field(name: &str) -> Token {
        Token::Field(name.into())
    }

    fn key(name: &'static str) -> Token {
        Token::Key { name, mods: vec![], repeat: 1 }
    }

    #[tokio::test]
    async fn default_sequence() {
        let tokens = parse("{USERNAME}{TAB}{PASSWORD}{ENTER}").unwrap();
        // Parsing takes no value: a placeholder stays a name.
        assert_eq!(tokens, [field("USERNAME"), key("Tab"), field("PASSWORD"), key("Return")]);
        // Special characters inside field values are typed literally.
        assert_eq!(
            typed("{USERNAME}{TAB}{PASSWORD}{ENTER}").await,
            ["text(madev,8)", "key(Tab,[],1)", "text(p@ss{}~+,8)", "key(Return,[],1)"]
        );
    }

    #[test]
    fn keys_repeats_delays_and_case() {
        let tokens = parse("{username}{tab 2}{Delay 300}{DELAY=50}{S:PIN}~").unwrap();
        assert_eq!(
            tokens,
            [
                field("USERNAME"),
                Token::Key { name: "Tab", mods: vec![], repeat: 2 },
                Token::Delay(300),
                Token::SetKeyDelay(50),
                field("S:PIN"),
                key("Return"),
            ]
        );
    }

    #[test]
    fn modifiers_and_literals() {
        let tokens = parse("^a+{TAB}x{+}{{}{}}y").unwrap();
        assert_eq!(
            tokens,
            [
                Token::Chord { text: 'a', mods: vec![Modifier::Ctrl] },
                Token::Key { name: "Tab", mods: vec![Modifier::Shift], repeat: 1 },
                text("x+{}y"),
            ]
        );
        let tokens = parse("{CLEARFIELD}{TOTP}").unwrap();
        assert_eq!(
            tokens,
            [
                Token::Key { name: "a", mods: vec![Modifier::Ctrl], repeat: 1 },
                key("BackSpace"),
                field("TOTP")
            ]
        );
    }

    #[tokio::test]
    async fn missing_fields_are_skipped_and_errors_reported() {
        assert_eq!(typed("{URL}{TAB}").await, ["key(Tab,[],1)"]);
        assert!(parse("{PICKCHARS}").unwrap_err().contains("Unsupported"));
        assert!(parse("{USERNAME").is_err());
        assert!(parse("{DELAY x}").is_err());
    }

    #[test]
    fn modifiers_before_fields_are_refused() {
        for sequence in ["+{PASSWORD}", "^{USERNAME}{TAB}", "+{S:PIN}", "{TAB}+{TOTP}"] {
            let err = parse(sequence).unwrap_err();
            assert!(err.contains("Modifiers before a field"), "{sequence}: {err}");
        }
        // Modifiers on keys and literal characters still work.
        assert!(parse("^a+{TAB}{PASSWORD}").is_ok());
    }

    #[test]
    fn focus_moving_keys_are_refused() {
        // A sequence from a shared database must not be able to Alt-Tab or open a launcher
        // before typing the password.
        for sequence in ["%{TAB}{PASSWORD}", "%a", "{WIN}", "{LWIN}r", "{RWIN}"] {
            assert!(parse(sequence).is_err(), "{sequence}");
        }
        assert!(parse("{%}").is_ok());
        assert!(parse(&"{TAB}".repeat(1000)).is_err(), "too long");
    }

    struct Long(usize);

    impl Fields for Long {
        fn field(&self, _: &str) -> Result<Option<Zeroizing<String>>, String> {
            Ok(Some(Zeroizing::new("x".repeat(self.0))))
        }
    }

    #[tokio::test]
    async fn long_text_is_chunked_and_capped() {
        let log = Log::default();
        run(&parse("{NOTES}").unwrap(), &Long(150), &mut Recorder(&log), 8).await.unwrap();
        let lens: Vec<usize> = log.take().iter().map(|s| s.len() - "text(,8)".len()).collect();
        assert_eq!(lens, [64, 64, 22]);

        let err =
            run(&parse("{NOTES}{NOTES}").unwrap(), &Long(5000), &mut Recorder(&log), 8).await.unwrap_err();
        assert!(err.contains("too much text"), "{err}");
    }

    #[tokio::test]
    async fn runs_tokens_in_order() {
        assert_eq!(
            typed("{USERNAME}{DELAY=3}{TAB}{PASSWORD}").await,
            ["text(madev,8)", "key(Tab,[],1)", "text(p@ss{}~+,3)"]
        );
    }

    /// Polls `future` once.
    async fn poll_once<F: Future + Unpin>(future: &mut F) -> std::task::Poll<F::Output> {
        std::future::poll_fn(|cx| std::task::Poll::Ready(std::pin::Pin::new(&mut *future).poll(cx))).await
    }

    /// A value is taken when it is about to be typed, so a pause before it passes without it,
    /// and stopping in the pause (dropping the future, which is what a lock does) means it was
    /// never taken at all.
    #[tokio::test]
    async fn a_field_is_looked_up_only_when_its_turn_comes() {
        let log = Log::default();
        let tokens = parse("{USERNAME}{TAB}{DELAY 50}{PASSWORD}{ENTER}").unwrap();
        let map = fields(&log);
        {
            let mut recorder = Recorder(&log);
            let mut typing = std::pin::pin!(run(&tokens, &map, &mut recorder, 8));
            // As far as it gets without waiting: up to the pause.
            assert!(poll_once(&mut typing).await.is_pending());
            assert_eq!(log.take(), ["field(USERNAME)", "text(madev,8)", "key(Tab,[],1)"]);
            typing.await.unwrap();
            assert_eq!(log.take(), ["field(PASSWORD)", "text(p@ss{}~+,8)", "key(Return,[],1)"]);
        }
        let mut recorder = Recorder(&log);
        let mut typing = std::pin::pin!(run(&tokens, &map, &mut recorder, 8));
        assert!(poll_once(&mut typing).await.is_pending());
        log.take();
        // Nothing follows from a future that is not polled again, which is all that dropping
        // it comes to.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(log.take(), [] as [&str; 0]);
    }

    /// One `wtype` is handed no more than it types in half a second, however slowly the keys
    /// are set to go, because that is how long it types on after a lock.
    #[test]
    fn a_burst_is_short_in_time() {
        let wtype = Wtype::new(&Tracker::default());
        for key_delay in [0, 8, 50, 200, 1000] {
            let burst = wtype.burst(key_delay).clamp(1, MAX_BURST_CHARS);
            let longest = typing_time(burst as u64, key_delay);
            assert!(
                longest <= Duration::from_millis(BURST_MILLIS.max(key_delay + KEY_MILLIS)),
                "{key_delay}"
            );
        }
        assert_eq!([0, 8, 200, 1000].map(|d| wtype.burst(d).clamp(1, MAX_BURST_CHARS)), [64, 41, 2, 1]);
    }

    #[test]
    fn wtype_args_wrap_modifiers() {
        assert_eq!(
            with_mods(&[Modifier::Ctrl, Modifier::Shift], ["-k".into(), "a".into()]),
            ["-M", "ctrl", "-M", "shift", "-k", "a", "-m", "shift", "-m", "ctrl"]
        );
    }
}
