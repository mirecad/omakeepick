//! Full-text fuzzy search over the entry index.
//!
//! Every word of the query must match at least one field (title, username, URL, group path,
//! tags, or notes). A word's score is its best weighted field score; an entry's score is the
//! sum over words plus a "frecency" bonus for entries used often and recently. The query uses
//! fzf syntax: `'exact`, `^prefix`, `suffix$`, `!exclude`.

use std::collections::HashMap;

use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};

use crate::vault::IndexedEntry;

/// How often and when (Unix seconds) an entry was last used, keyed by entry UUID.
pub type Usage = HashMap<String, (u32, i64)>;

const TITLE: u32 = 4;
const USERNAME: u32 = 3;
const URL: u32 = 2;
const GROUP: u32 = 2;
const TAGS: u32 = 2;
const NOTES: u32 = 1;

/// Fuzzy matches inside long free text are mostly noise, so notes only match as substrings.
fn substring_variant(atom: &Atom) -> Atom {
    if atom.kind != AtomKind::Fuzzy {
        return atom.clone();
    }
    let needle: String = atom.needle_text().chars().collect();
    Atom::new(&needle, CaseMatching::Ignore, Normalization::Smart, AtomKind::Substring, false)
}

/// Bonus for entries used often and recently: `ln(1 + uses)` that halves every 30 days.
pub fn frecency(usage: Option<&(u32, i64)>, now: i64) -> u32 {
    let Some(&(count, last)) = usage else { return 0 };
    let age_days = (now - last).max(0) as f64 / 86_400.0;
    (f64::from(count).ln_1p() * 120.0 * 0.5f64.powf(age_days / 30.0)) as u32
}

pub struct Searcher {
    matcher: Matcher,
    buf: Vec<char>,
}

impl Default for Searcher {
    fn default() -> Self {
        let mut config = Config::DEFAULT;
        config.prefer_prefix = true;
        Searcher { matcher: Matcher::new(config), buf: Vec::new() }
    }
}

impl Searcher {
    fn score(&mut self, atom: &Atom, haystack: &str) -> Option<u32> {
        if haystack.is_empty() {
            return if atom.negative { Some(0) } else { None };
        }
        // nucleo folds case only for some non-ASCII letters (`Ž` stays unmatched by `z`), so
        // lowercase those haystacks first; its normalization then maps `ž` to `z`.
        let folded;
        let haystack = if haystack.is_ascii() {
            haystack
        } else {
            folded = haystack.to_lowercase();
            &folded
        };
        atom.score(Utf32Str::new(haystack, &mut self.buf), &mut self.matcher).map(u32::from)
    }

    fn score_entry(&mut self, entry: &IndexedEntry, atoms: &[(Atom, Atom)]) -> Option<u32> {
        let mut total = 0;
        for (atom, notes_atom) in atoms {
            let fields = [
                (entry.title.as_str(), TITLE),
                (entry.username.as_str(), USERNAME),
                (entry.url_match.as_str(), URL),
                (entry.group.as_str(), GROUP),
                (entry.tags.as_str(), TAGS),
            ];
            if atom.negative {
                // A negative atom scores `None` on any field containing the excluded text.
                let excluded = fields.iter().any(|(text, _)| self.score(atom, text).is_none())
                    || self.score(notes_atom, &entry.notes).is_none();
                if excluded {
                    return None;
                }
                continue;
            }
            let mut best =
                fields.iter().filter_map(|&(text, weight)| self.score(atom, text).map(|s| s * weight)).max();
            if let Some(notes) = self.score(notes_atom, &entry.notes) {
                best = best.max(Some(notes * NOTES));
            }
            total += best?;
        }
        Some(total)
    }

    /// Returns indices into `index`, best first, and the number of matches before `limit`.
    pub fn search(
        &mut self,
        index: &[IndexedEntry],
        query: &str,
        usage: &Usage,
        limit: usize,
        recent: usize,
        now: i64,
    ) -> (Vec<usize>, usize) {
        let pattern = Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart);
        if pattern.atoms.is_empty() {
            let mut used: Vec<(usize, u32, i64)> = index
                .iter()
                .enumerate()
                .filter_map(|(i, e)| usage.get(&e.uuid).map(|u| (i, frecency(Some(u), now), u.1)))
                .collect();
            used.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
            let total = used.len();
            return (used.into_iter().take(recent.min(limit)).map(|(i, ..)| i).collect(), total);
        }
        let atoms: Vec<(Atom, Atom)> =
            pattern.atoms.iter().map(|a| (a.clone(), substring_variant(a))).collect();
        let mut hits: Vec<(usize, u32)> = index
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                self.score_entry(e, &atoms).map(|s| (i, s + frecency(usage.get(&e.uuid), now)))
            })
            .collect();
        // Ties go to the shorter (more specific) title; `index` is sorted by title, so the
        // stable sort keeps remaining ties alphabetical.
        hits.sort_by(|a, b| b.1.cmp(&a.1).then(index[a.0].title.len().cmp(&index[b.0].title.len())));
        let total = hits.len();
        (hits.into_iter().take(limit).map(|(i, _)| i).collect(), total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, username: &str, url: &str, group: &str, notes: &str) -> IndexedEntry {
        IndexedEntry {
            id: keepass::db::EntryId::new(),
            uuid: title.to_string(),
            title: title.into(),
            username: username.into(),
            url: url.into(),
            url_match: url.into(),
            group: group.into(),
            tags: String::new(),
            notes: notes.into(),
            has_password: true,
            has_totp: false,
            autotype: true,
        }
    }

    fn index() -> Vec<IndexedEntry> {
        let mut v = vec![
            entry("GitHub", "madev", "github.com/login", "Personal/Dev", ""),
            entry("GitLab work", "m.adamec", "gitlab.example.com", "Work", ""),
            entry("Gitea home server", "admin", "gitea.lan:3000", "Homelab", ""),
            entry("Jira", "madev@work", "", "Work", "Ask IT for the recovery codes."),
            entry("Kancelária Žilina", "recepcia", "", "Work", ""),
            entry("Bank", "1234567", "ib.bank.sk", "Personal", ""),
        ];
        v.sort_by_key(|e| e.title.to_lowercase());
        v
    }

    fn titles(query: &str, usage: &Usage) -> Vec<String> {
        let index = index();
        let (hits, _) = Searcher::default().search(&index, query, usage, 50, 8, 1_000_000);
        hits.into_iter().map(|i| index[i].title.clone()).collect()
    }

    #[test]
    fn title_prefix_wins() {
        let t = titles("git", &Usage::new());
        assert_eq!(t.len(), 3);
        assert_eq!(t[0], "GitHub");
        assert!(!t.contains(&"Jira".to_string()));
    }

    #[test]
    fn words_may_match_different_fields() {
        assert_eq!(titles("work git", &Usage::new()), ["GitLab work"]);
        assert_eq!(titles("madev jira", &Usage::new()), ["Jira"]);
        assert_eq!(titles("personal bank", &Usage::new()), ["Bank"]);
    }

    #[test]
    fn notes_match_only_as_substring() {
        assert_eq!(titles("recovery", &Usage::new()), ["Jira"]);
        assert!(titles("rcvry", &Usage::new()).is_empty());
    }

    #[test]
    fn ignores_case_and_diacritics() {
        assert_eq!(titles("kancelaria zilina", &Usage::new()), ["Kancelária Žilina"]);
        assert_eq!(titles("BANK", &Usage::new()), ["Bank"]);
    }

    #[test]
    fn fzf_syntax() {
        assert_eq!(titles("git !work", &Usage::new()), ["GitHub", "Gitea home server"]);
        assert_eq!(titles("'lan:3000", &Usage::new()), ["Gitea home server"]);
    }

    #[test]
    fn frecency_breaks_near_ties() {
        let mut usage = Usage::new();
        usage.insert("Gitea home server".into(), (25, 1_000_000));
        assert_eq!(titles("git", &usage)[0], "Gitea home server");
    }

    #[test]
    fn empty_query_lists_recent_entries() {
        assert!(titles("", &Usage::new()).is_empty());
        let mut usage = Usage::new();
        usage.insert("Bank".into(), (1, 1_000_000));
        usage.insert("Jira".into(), (5, 1_000_000 - 86_400));
        usage.insert("Gone".into(), (9, 1_000_000));
        assert_eq!(titles("  ", &usage), ["Jira", "Bank"]);
    }

    #[test]
    fn frecency_decays() {
        let now = 100 * 86_400;
        let fresh = frecency(Some(&(10, now)), now);
        let old = frecency(Some(&(10, now - 30 * 86_400)), now);
        assert!(fresh > 0 && (old as f64 - fresh as f64 / 2.0).abs() <= 1.0);
        assert_eq!(frecency(None, now), 0);
    }
}
