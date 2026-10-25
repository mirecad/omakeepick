//! Runtime settings pushed by the shell plugin with the `configure` command.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub idle_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
    pub autotype_sequence: String,
    pub type_delay_ms: u32,
    pub autotype_start_delay_ms: u32,
    pub recent_count: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            idle_lock_minutes: 30,
            clipboard_clear_seconds: 15,
            autotype_sequence: DEFAULT_SEQUENCE.to_string(),
            type_delay_ms: 8,
            autotype_start_delay_ms: 250,
            recent_count: 8,
        }
    }
}

impl Settings {
    /// Returns a copy with the known keys of `patch` applied. Unknown keys are ignored so the
    /// plugin can keep plugin-only settings (like `notifyOnCopy`) in the same object.
    pub fn merged(&self, patch: &Value) -> Result<Settings, String> {
        let Value::Object(patch) = patch else {
            return Err("settings must be an object".into());
        };
        let mut current = serde_json::to_value(self).map_err(|e| e.to_string())?;
        if let Value::Object(map) = &mut current {
            for (key, value) in patch {
                if map.contains_key(key) && !value.is_null() {
                    map.insert(key.clone(), value.clone());
                }
            }
        }
        let mut next: Settings =
            serde_json::from_value(current).map_err(|e| format!("invalid settings: {e}"))?;
        next.clamp();
        Ok(next)
    }

    fn clamp(&mut self) {
        self.idle_lock_minutes = self.idle_lock_minutes.min(24 * 60);
        self.clipboard_clear_seconds = self.clipboard_clear_seconds.min(600);
        self.type_delay_ms = self.type_delay_ms.min(200);
        self.autotype_start_delay_ms = self.autotype_start_delay_ms.clamp(50, 5000);
        self.recent_count = self.recent_count.min(50);
        if self.autotype_sequence.trim().is_empty() {
            self.autotype_sequence = DEFAULT_SEQUENCE.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_applies_known_keys_only() {
        let s = Settings::default()
            .merged(&json!({"idleLockMinutes": 5, "notifyOnCopy": false, "typeDelayMs": null}))
            .unwrap();
        assert_eq!(s.idle_lock_minutes, 5);
        assert_eq!(s.type_delay_ms, Settings::default().type_delay_ms);
    }

    #[test]
    fn merge_rejects_wrong_types_and_clamps() {
        assert!(Settings::default().merged(&json!({"idleLockMinutes": "x"})).is_err());
        let s = Settings::default()
            .merged(&json!({"autotypeStartDelayMs": 0, "autotypeSequence": "  "}))
            .unwrap();
        assert_eq!(s.autotype_start_delay_ms, 50);
        assert_eq!(s.autotype_sequence, DEFAULT_SEQUENCE);
    }
}
