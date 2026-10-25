//! Line-delimited JSON framing (see `docs/PROTOCOL.md`).

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::{Zeroize, Zeroizing};

/// Longest accepted request line. Requests are tiny; this only bounds memory.
const MAX_LINE: usize = 1 << 20;

#[derive(Debug, Deserialize)]
pub struct Header {
    pub id: Option<i64>,
    pub cmd: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
    pub extra: Map<String, Value>,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into(), extra: Map::new() }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::new("bad_request", message)
    }

    pub fn locked() -> Self {
        ApiError::new("locked", "The database is locked")
    }
}

impl From<crate::vault::VaultError> for ApiError {
    fn from(err: crate::vault::VaultError) -> Self {
        ApiError::new(err.code(), err.to_string())
    }
}

pub type Reply = Result<Map<String, Value>, ApiError>;

pub fn ok() -> Reply {
    Ok(Map::new())
}

pub fn ok_with(value: Value) -> Reply {
    match value {
        Value::Object(map) => Ok(map),
        other => Ok(Map::from_iter([("result".to_string(), other)])),
    }
}

pub fn encode_reply(id: Option<i64>, reply: Reply) -> String {
    let mut map = match reply {
        Ok(map) => {
            let mut out = Map::from_iter([("ok".to_string(), json!(true))]);
            out.extend(map);
            out
        }
        Err(err) => {
            let mut out = Map::from_iter([
                ("ok".to_string(), json!(false)),
                ("error".to_string(), json!(err.code)),
                ("message".to_string(), json!(err.message)),
            ]);
            out.extend(err.extra);
            out
        }
    };
    map.insert("id".into(), id.map_or(Value::Null, Value::from));
    let mut line = Value::Object(map).to_string();
    line.push('\n');
    line
}

/// Parses the arguments of a request from its raw line.
pub fn args<'de, T: Deserialize<'de>>(line: &'de [u8]) -> Result<T, ApiError> {
    serde_json::from_slice(line).map_err(|e| ApiError::bad_request(format!("Invalid arguments: {e}")))
}

/// Reads `\n`-terminated lines and wipes consumed bytes from its buffer, since request lines
/// can carry the master password or PIN.
pub struct SecretLines<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> SecretLines<R> {
    pub fn new(inner: R) -> Self {
        SecretLines { inner, buf: Vec::with_capacity(4096) }
    }

    /// Returns the next line without the newline, or `None` at end of stream.
    pub async fn next_line(&mut self) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
        let mut chunk = Zeroizing::new([0u8; 4096]);
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let line = Zeroizing::new(self.buf[..pos].to_vec());
                let rest = self.buf.len() - (pos + 1);
                self.buf.copy_within(pos + 1.., 0);
                self.buf[rest..].zeroize();
                self.buf.truncate(rest);
                return Ok(Some(line));
            }
            if self.buf.len() > MAX_LINE {
                self.buf.zeroize();
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request line too long"));
            }
            let n = self.inner.read(chunk.as_mut()).await?;
            if n == 0 {
                self.buf.zeroize();
                return Ok(None);
            }
            // Grow by copying into a fresh buffer so no stale copy is left behind by realloc.
            if self.buf.len() + n > self.buf.capacity() {
                let mut grown = Vec::with_capacity((self.buf.len() + n).next_power_of_two());
                grown.extend_from_slice(&self.buf);
                self.buf.zeroize();
                self.buf = grown;
            }
            self.buf.extend_from_slice(&chunk[..n]);
            chunk[..n].zeroize();
        }
    }
}

impl<R> Drop for SecretLines<R> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn splits_lines_across_reads() {
        let data: &[u8] = b"{\"id\":1}\n{\"id\"";
        let mut lines = SecretLines::new(data.chain(&b":2}\n\n"[..]));
        assert_eq!(&**lines.next_line().await.unwrap().unwrap(), b"{\"id\":1}");
        assert_eq!(&**lines.next_line().await.unwrap().unwrap(), b"{\"id\":2}");
        assert_eq!(&**lines.next_line().await.unwrap().unwrap(), b"");
        assert!(lines.next_line().await.unwrap().is_none());
    }

    #[test]
    fn encodes_replies() {
        let ok_line = encode_reply(Some(3), ok_with(json!({"total": 2})));
        let v: Value = serde_json::from_str(&ok_line).unwrap();
        assert_eq!(v, json!({"id": 3, "ok": true, "total": 2}));
        let err_line = encode_reply(None, Err(ApiError::new("bad_pin", "Wrong PIN").with("attemptsLeft", 2)));
        let v: Value = serde_json::from_str(&err_line).unwrap();
        assert_eq!(
            v,
            json!({"id": null, "ok": false, "error": "bad_pin", "message": "Wrong PIN", "attemptsLeft": 2})
        );
    }
}
