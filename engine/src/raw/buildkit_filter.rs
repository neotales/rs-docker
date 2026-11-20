//! Bounded fsutil filters using Moby patternmatcher v0.6.1 parent results.
//! Source: tonistiigi/fsutil e075fd9305eb `filter.go` and moby/patternmatcher
//! v0.6.1 `patternmatcher.go`. No filtered-out file data is sent to the peer.

use regex::Regex;

use super::buildkit_context::Snapshot;

const MAX_PATTERNS: usize = 4096;
const MAX_BYTES: usize = 64 * 1024;

struct Pattern {
    regex: Regex,
    negated: bool,
}

struct Matcher(Vec<Pattern>);

impl Matcher {
    fn new(patterns: &[String]) -> Result<Self, ()> {
        if patterns.len() > MAX_PATTERNS
            || patterns.iter().map(String::len).sum::<usize>() > MAX_BYTES
        {
            return Err(());
        }
        let mut compiled = Vec::new();
        for pattern in patterns {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                continue;
            }
            // Absolute and escaping patterns are outside a session root;
            // reject rather than silently reinterpreting them as relative.
            let bare = pattern.strip_prefix('!').unwrap_or(pattern);
            if bare.starts_with('/') || bare.split('/').any(|part| part == "..") {
                return Err(());
            }
            // Go's regexp conversion treats a bare `^` as an anchor when a
            // pattern also has metacharacters, while our shared compiler
            // treats it literally. Refuse this uncommon ambiguous form rather
            // than risk leaking a file that the daemon intended to exclude.
            if bare.contains(['*', '?', '[', '\\']) && bare_caret(bare) {
                return Err(());
            }
            let cleaned = crate::build_ignore::clean_pattern(pattern);
            let (negated, pattern) = cleaned
                .strip_prefix('!')
                .map_or((false, cleaned.as_str()), |s| (true, s));
            if pattern.is_empty() {
                return Err(());
            }
            let expression = crate::build_ignore::compile_pattern(pattern)?;
            compiled.push(Pattern {
                regex: Regex::new(&expression).map_err(|_| ())?,
                negated,
            });
        }
        Ok(Self(compiled))
    }

    fn matches(&self, path: &str, parent: &[bool]) -> (bool, Vec<bool>) {
        let mut matched = false;
        let mut results = vec![false; self.0.len()];
        for (index, pattern) in self.0.iter().enumerate() {
            let inherited = parent.get(index).copied().unwrap_or(false);
            if !inherited && pattern.negated != matched {
                continue;
            }
            let hit = inherited || pattern.regex.is_match(path);
            results[index] = hit;
            if hit {
                matched = !pattern.negated;
            }
        }
        (matched, results)
    }
}

fn bare_caret(pattern: &str) -> bool {
    let mut class = false;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' => class = true,
            ']' => class = false,
            '^' if !class => return true,
            _ => {}
        }
    }
    false
}

/// Select entries in fsutil walk order and restore omitted parent directories.
pub(super) fn select(
    snapshot: &Snapshot,
    includes: &[String],
    excludes: &[String],
) -> Result<Vec<usize>, ()> {
    let include = Matcher::new(includes)?;
    let exclude = Matcher::new(excludes)?;
    let mut dirs: Vec<(usize, Vec<bool>, Vec<bool>)> = Vec::new();
    let mut selected = vec![false; snapshot.entries.len()];
    for (index, entry) in snapshot.entries.iter().enumerate() {
        let path = &entry.stat.path;
        while dirs.last().is_some_and(|(parent, _, _)| {
            !path
                .strip_prefix(&snapshot.entries[*parent].stat.path)
                .is_some_and(|tail| tail.starts_with('/'))
        }) {
            dirs.pop();
        }
        let parent_include = dirs.last().map_or(&[][..], |(_, info, _)| info);
        let parent_exclude = dirs.last().map_or(&[][..], |(_, _, info)| info);
        let (allow, include_results) = include.matches(path, parent_include);
        let (deny, exclude_results) = exclude.matches(path, parent_exclude);
        let keep = (include.0.is_empty() || allow) && !deny;
        if keep {
            selected[index] = true;
            for (parent, _, _) in &dirs {
                selected[*parent] = true;
            }
        }
        if entry.data.is_none() {
            dirs.push((index, include_results, exclude_results));
        }
    }
    Ok(selected
        .into_iter()
        .enumerate()
        .filter_map(|(index, keep)| keep.then_some(index))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::buildkit_context::{Entry, Snapshot};
    use neotales_docker_buildkit::proto::FileStat;

    fn fixture() -> Snapshot {
        Snapshot {
            entries: [
                ("dir", false),
                ("dir/keep.txt", true),
                ("dir/drop.key", true),
                ("other", false),
                ("other/a.key", true),
                ("root.key", true),
            ]
            .into_iter()
            .map(|(path, file)| Entry {
                stat: FileStat {
                    path: path.into(),
                    ..FileStat::default()
                },
                data: file.then(Vec::new),
            })
            .collect(),
        }
    }

    #[test]
    fn ordered_exclusions_restore_parents() {
        let selected =
            select(&fixture(), &[], &["**/*.key".into(), "!other/a.key".into()]).unwrap();
        assert_eq!(selected, [0, 1, 3, 4]);
    }

    #[test]
    fn includes_keep_ancestors_and_descendants() {
        assert_eq!(
            select(&fixture(), &["dir/keep.txt".into()], &[]).unwrap(),
            [0, 1]
        );
        assert_eq!(select(&fixture(), &["dir".into()], &[]).unwrap(), [0, 1, 2]);
    }

    #[test]
    fn unsafe_and_invalid_patterns_are_refused() {
        for pattern in ["../x", "/x", "!", "[", "^prefix*"] {
            assert!(select(&fixture(), &[], &[pattern.into()]).is_err());
        }
    }
}
