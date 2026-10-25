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
//! Secrets are piped to `wtype -` on stdin; they never appear on a command line.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

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

#[derive(Debug, PartialEq)]
pub enum Token {
    /// Text to type literally. May contain secrets.
    Text(Zeroizing<String>),
    /// An xkb keysym name, pressed `repeat` times with `mods` held.
    Key {
        name: &'static str,
        mods: Vec<Modifier>,
        repeat: u32,
    },
    /// A single character typed with modifiers held (`^a`).
    Chord {
        text: char,
        mods: Vec<Modifier>,
    },
    Delay(u64),
    SetKeyDelay(u64),
}

/// Resolves field placeholders (`USERNAME`, `S:Name`, `TOTP`, …) to their values.
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
        "WIN" | "LWIN" => "Super_L",
        "RWIN" => "Super_R",
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
}

impl Builder {
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
        if let Some(Token::Text(prev)) = self.tokens.last_mut() {
            prev.push_str(rest);
        } else {
            self.tokens.push(Token::Text(Zeroizing::new(rest.to_string())));
        }
    }

    fn key(&mut self, name: &'static str, repeat: u32) {
        let mods = std::mem::take(&mut self.mods);
        self.tokens.push(Token::Key { name, mods, repeat });
    }

    fn plain(&mut self, token: Token) {
        self.mods.clear();
        self.tokens.push(token);
    }
}

pub fn parse(sequence: &str, fields: &dyn Fields) -> Result<Vec<Token>, String> {
    let mut b = Builder { tokens: Vec::new(), mods: Vec::new() };
    let mut chars = sequence.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '+' => b.mods.push(Modifier::Shift),
            '^' => b.mods.push(Modifier::Ctrl),
            '%' => b.mods.push(Modifier::Alt),
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
                        None => return Err(format!("Unclosed placeholder {{{inner}")),
                    }
                }
                placeholder(&mut b, &inner, fields)?;
            }
            other => b.text(other.encode_utf8(&mut [0; 4])),
        }
    }
    Ok(b.tokens)
}

fn placeholder(b: &mut Builder, inner: &str, fields: &dyn Fields) -> Result<(), String> {
    if matches!(inner, "+" | "^" | "%" | "~" | "{" | "(" | ")" | "[" | "]") {
        b.text(inner);
        return Ok(());
    }
    let upper = inner.to_uppercase();
    if let Some(ms) = upper.strip_prefix("DELAY=") {
        let ms = ms.trim().parse().map_err(|_| format!("Invalid {{{inner}}}"))?;
        b.plain(Token::SetKeyDelay(ms));
        return Ok(());
    }
    if let Some(ms) = upper.strip_prefix("DELAY ") {
        let ms = ms.trim().parse().map_err(|_| format!("Invalid {{{inner}}}"))?;
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
        Some((name, count)) if count.chars().all(|c| c.is_ascii_digit()) => {
            (name.to_string(), count.parse::<u32>().map_err(|_| format!("Invalid {{{inner}}}"))?)
        }
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
        _ => return Err(format!("Unsupported auto-type placeholder {{{inner}}}")),
    };
    match fields.field(&field_name)? {
        Some(value) => b.text(&value),
        None => b.mods.clear(),
    }
    Ok(())
}

/// Sends tokens to the focused window.
#[allow(async_fn_in_trait)] // only used with concrete types on one thread
pub trait Typist {
    async fn text(&mut self, text: &str, key_delay: u64) -> Result<(), String>;
    async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String>;
    async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String>;
}

pub async fn run(tokens: &[Token], typist: &mut impl Typist, key_delay: u64) -> Result<(), String> {
    let mut delay = key_delay;
    for token in tokens {
        match token {
            Token::Text(text) => typist.text(text, delay).await?,
            Token::Key { name, mods, repeat } => typist.key(name, mods, *repeat).await?,
            Token::Chord { text, mods } => typist.chord(*text, mods).await?,
            Token::Delay(ms) => tokio::time::sleep(Duration::from_millis((*ms).min(10_000))).await,
            Token::SetKeyDelay(ms) => delay = (*ms).min(1000),
        }
    }
    Ok(())
}

async fn wtype(args: &[String], stdin: Option<&[u8]>) -> Result<(), String> {
    let mut child = Command::new("wtype")
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "tool_missing:wtype is not installed".to_string(),
            _ => format!("Cannot run wtype: {e}"),
        })?;
    if let Some(data) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(data).await.map_err(|e| format!("wtype: {e}"))?;
    }
    let out = child.wait_with_output().await.map_err(|e| format!("wtype: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("wtype failed: {}", err.trim()));
    }
    // Give the compositor a moment between virtual keyboards so events stay in order.
    tokio::time::sleep(Duration::from_millis(12)).await;
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

/// Types with the virtual-keyboard protocol. Works for native Wayland windows.
pub struct Wtype;

impl Typist for Wtype {
    async fn text(&mut self, text: &str, key_delay: u64) -> Result<(), String> {
        wtype(&["-d".into(), key_delay.to_string(), "-".into()], Some(text.as_bytes())).await
    }

    async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String> {
        let keys = (0..repeat).flat_map(|_| ["-k".to_string(), name.to_string()]);
        wtype(&with_mods(mods, keys), None).await
    }

    async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String> {
        wtype(&with_mods(mods, ["--".to_string(), text.to_string()]), None).await
    }
}

/// XWayland windows mis-handle wtype's per-character keymaps, so text is pasted instead:
/// copied (as sensitive) to both clipboard and primary selection, then Shift+Insert.
/// Both selections are cleared when the typist is dropped.
#[derive(Default)]
pub struct PasteTypist {
    used: bool,
}

impl PasteTypist {
    pub async fn finish(self) {
        if self.used {
            tokio::time::sleep(Duration::from_millis(300)).await;
            crate::clipboard::clear_all().await;
        }
    }
}

impl Typist for PasteTypist {
    async fn text(&mut self, text: &str, _key_delay: u64) -> Result<(), String> {
        self.used = true;
        crate::clipboard::set(text.as_bytes(), false).await?;
        crate::clipboard::set(text.as_bytes(), true).await?;
        tokio::time::sleep(Duration::from_millis(60)).await;
        wtype(&with_mods(&[Modifier::Shift], ["-k".into(), "Insert".into()]), None).await?;
        // The application reads the selection asynchronously.
        tokio::time::sleep(Duration::from_millis(250)).await;
        Ok(())
    }

    async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String> {
        Wtype.key(name, mods, repeat).await
    }

    async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String> {
        Wtype.chord(text, mods).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Map(HashMap<&'static str, &'static str>);

    impl Fields for Map {
        fn field(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
            Ok(self.0.get(name).map(|v| Zeroizing::new(v.to_string())))
        }
    }

    fn fields() -> Map {
        Map(HashMap::from([
            ("USERNAME", "madev"),
            ("PASSWORD", "p@ss{}~+"),
            ("S:PIN", "4321"),
            ("TOTP", "123456"),
        ]))
    }

    fn text(s: &str) -> Token {
        Token::Text(Zeroizing::new(s.into()))
    }

    fn key(name: &'static str) -> Token {
        Token::Key { name, mods: vec![], repeat: 1 }
    }

    #[test]
    fn default_sequence() {
        let tokens = parse("{USERNAME}{TAB}{PASSWORD}{ENTER}", &fields()).unwrap();
        // Special characters inside field values are typed literally.
        assert_eq!(tokens, [text("madev"), key("Tab"), text("p@ss{}~+"), key("Return")]);
    }

    #[test]
    fn keys_repeats_delays_and_case() {
        let tokens = parse("{username}{tab 2}{Delay 300}{DELAY=50}{S:PIN}~", &fields()).unwrap();
        assert_eq!(
            tokens,
            [
                text("madev"),
                Token::Key { name: "Tab", mods: vec![], repeat: 2 },
                Token::Delay(300),
                Token::SetKeyDelay(50),
                text("4321"),
                key("Return"),
            ]
        );
    }

    #[test]
    fn modifiers_and_literals() {
        let tokens = parse("^a+{TAB}x{+}{{}{}}y", &fields()).unwrap();
        assert_eq!(
            tokens,
            [
                Token::Chord { text: 'a', mods: vec![Modifier::Ctrl] },
                Token::Key { name: "Tab", mods: vec![Modifier::Shift], repeat: 1 },
                text("x+{}y"),
            ]
        );
        let tokens = parse("{CLEARFIELD}{TOTP}", &fields()).unwrap();
        assert_eq!(
            tokens,
            [
                Token::Key { name: "a", mods: vec![Modifier::Ctrl], repeat: 1 },
                key("BackSpace"),
                text("123456"),
            ]
        );
    }

    #[test]
    fn missing_fields_are_skipped_and_errors_reported() {
        assert_eq!(parse("{URL}{TAB}", &fields()).unwrap(), [key("Tab")]);
        assert!(parse("{PICKCHARS}", &fields()).unwrap_err().contains("Unsupported"));
        assert!(parse("{USERNAME", &fields()).is_err());
        assert!(parse("{DELAY x}", &fields()).is_err());
    }

    #[derive(Default)]
    struct Recorder(Vec<String>);

    impl Typist for Recorder {
        async fn text(&mut self, text: &str, key_delay: u64) -> Result<(), String> {
            self.0.push(format!("text({text},{key_delay})"));
            Ok(())
        }
        async fn key(&mut self, name: &str, mods: &[Modifier], repeat: u32) -> Result<(), String> {
            self.0.push(format!("key({name},{mods:?},{repeat})"));
            Ok(())
        }
        async fn chord(&mut self, text: char, mods: &[Modifier]) -> Result<(), String> {
            self.0.push(format!("chord({text},{mods:?})"));
            Ok(())
        }
    }

    #[tokio::test]
    async fn runs_tokens_in_order() {
        let tokens = parse("{USERNAME}{DELAY=3}{TAB}{PASSWORD}", &fields()).unwrap();
        let mut rec = Recorder::default();
        run(&tokens, &mut rec, 8).await.unwrap();
        assert_eq!(rec.0, ["text(madev,8)", "key(Tab,[],1)", "text(p@ss{}~+,3)"]);
    }

    #[test]
    fn wtype_args_wrap_modifiers() {
        assert_eq!(
            with_mods(&[Modifier::Ctrl, Modifier::Shift], ["-k".into(), "a".into()]),
            ["-M", "ctrl", "-M", "shift", "-k", "a", "-m", "shift", "-m", "ctrl"]
        );
    }
}
