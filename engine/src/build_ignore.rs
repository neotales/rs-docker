//! Dockerignore matching for the deliberately supported, bounded subset.
use super::{ImageTransferError, ImageTransferLimits};
use regex::Regex;
use std::{borrow::Cow, fmt::Write as _, fs, io::Read, path::Path};

const MAX_IGNORE_BYTES: u64 = 64 * 1024;
const MAX_PATTERNS: usize = 4096;

#[derive(Debug)]
struct Pattern {
    expression: Regex,
    negated: bool,
}

#[derive(Debug)]
pub(super) struct BuildIgnore {
    patterns: Vec<Pattern>,
    pub(super) selected: String,
}

fn invalid(detail: impl Into<String>) -> ImageTransferError {
    ImageTransferError::InvalidOption {
        name: "dockerignore",
        detail: detail.into(),
    }
}

#[cfg(windows)]
fn platform_separators(pattern: &str) -> Cow<'_, str> {
    Cow::Owned(pattern.replace('\\', "/"))
}

#[cfg(not(windows))]
fn platform_separators(pattern: &str) -> Cow<'_, str> {
    Cow::Borrowed(pattern)
}

// Normalize platform separators before the slash-based equivalent of Go's
// filepath.Clean. Unix backslashes must remain escapes, not separators.
pub(crate) fn clean_pattern(pattern: &str) -> String {
    let pattern = platform_separators(pattern);
    let absolute = pattern.starts_with('/');
    let mut components = Vec::new();
    for component in pattern.split('/') {
        match component {
            "" | "." => {}
            ".." if components.last().is_some_and(|part| *part != "..") => {
                components.pop();
            }
            ".." if absolute => {}
            part => components.push(part),
        }
    }
    components.join("/")
}

fn class_char(chars: &[char], position: &mut usize) -> Result<char, ()> {
    let mut c = *chars.get(*position).ok_or(())?;
    if c == '\\' {
        *position += 1;
        c = *chars.get(*position).ok_or(())?;
    } else if c == '-' || c == ']' {
        return Err(());
    }
    *position += 1;
    Ok(c)
}

fn compile_class(chars: &[char], position: &mut usize) -> Result<String, ()> {
    let negated = chars.get(*position) == Some(&'^');
    if negated {
        *position += 1;
    }
    let mut ranges = String::new();
    let mut count = 0;
    while chars.get(*position) != Some(&']') {
        let lo = class_char(chars, position)?;
        let hi = if chars.get(*position) == Some(&'-') {
            *position += 1;
            class_char(chars, position)?
        } else {
            lo
        };
        if lo > hi {
            return Err(());
        }
        count += 1;
        write!(ranges, "\\x{{{:x}}}", u32::from(lo)).map_err(|_| ())?;
        if lo != hi {
            write!(ranges, "-\\x{{{:x}}}", u32::from(hi)).map_err(|_| ())?;
        }
    }
    *position += 1;
    if count == 0 {
        return Err(());
    }
    Ok(format!("[{}{ranges}]", if negated { "^" } else { "" }))
}

pub(crate) fn compile_pattern(pattern: &str) -> Result<String, ()> {
    // Moby uses a suffix fast path when a leading ** is followed exclusively
    // by literal characters. Unlike the regex case, **foo matches xfoo.
    if let Some(suffix) = pattern.strip_prefix("**")
        && !suffix.is_empty()
        && !suffix.contains(['*', '?', '[', '\\'])
    {
        let body = suffix.strip_prefix('/').map_or_else(
            || format!(".*{}", regex::escape(suffix)),
            |value| format!("(?:.*/)?{}", regex::escape(value)),
        );
        return Ok(format!("^{body}$"));
    }
    let chars: Vec<_> = pattern.chars().collect();
    let mut source = String::from("^");
    let mut position = 0;
    while let Some(&c) = chars.get(position) {
        position += 1;
        match c {
            '*' => {
                if chars.get(position) == Some(&'*') {
                    position += 1;
                    if chars.get(position) == Some(&'/') {
                        position += 1;
                    }
                    source.push_str(if position == chars.len() {
                        ".*"
                    } else {
                        "(?:.*/)?"
                    });
                } else {
                    source.push_str("[^/]*");
                }
            }
            '?' => source.push_str("[^/]"),
            '[' => source.push_str(&compile_class(&chars, &mut position)?),
            '\\' => {
                let escaped = *chars.get(position).ok_or(())?;
                position += 1;
                source.push_str(&regex::escape(&escaped.to_string()));
            }
            _ => source.push_str(&regex::escape(&c.to_string())),
        }
    }
    source.push('$');
    Ok(source)
}

impl BuildIgnore {
    #[allow(clippy::too_many_lines)]
    pub(super) fn load(
        root: &Path,
        dockerfile: &str,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let specific = format!("{dockerfile}.dockerignore");
        let mut parent = root.to_path_buf();
        for component in dockerfile
            .split('/')
            .take(dockerfile.split('/').count() - 1)
        {
            parent.push(component);
            match fs::symlink_metadata(&parent) {
                Ok(metadata) if super::is_link_or_reparse_point(&metadata) => {
                    return Err(invalid("Dockerfile parent is a symbolic link"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(ImageTransferError::Io(error.to_string())),
            }
        }
        let selected = match fs::symlink_metadata(root.join(&specific)) {
            Ok(_) => specific,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ".dockerignore".to_owned()
            }
            Err(error) => return Err(ImageTransferError::Io(error.to_string())),
        };
        let path = root.join(&selected);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    patterns: Vec::new(),
                    selected,
                });
            }
            Err(error) => return Err(ImageTransferError::Io(error.to_string())),
        };
        if super::is_link_or_reparse_point(&metadata) || !metadata.is_file() {
            return Err(invalid("ignore file must be a regular file"));
        }
        let max = MAX_IGNORE_BYTES.min(limits.max_entry_bytes);
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(max + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max {
            return Err(invalid("ignore file exceeds size limit"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("ignore file is not UTF-8"))?;
        let patterns = parse_patterns(text)?;
        Ok(Self { patterns, selected })
    }

    pub(super) fn excluded(&self, path: &str) -> bool {
        let mut excluded = false;
        for pattern in &self.patterns {
            if pattern.negated != excluded {
                continue;
            }
            if pattern.expression.is_match(path)
                || path
                    .match_indices('/')
                    .any(|(i, _)| pattern.expression.is_match(&path[..i]))
            {
                excluded = !pattern.negated;
            }
        }
        excluded
    }
}

fn parse_patterns(text: &str) -> Result<Vec<Pattern>, ImageTransferError> {
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_IGNORE_BYTES {
        return Err(invalid("ignore rules exceed size limit"));
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut patterns = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line == "." {
            continue;
        }
        let (negated, line) = line.strip_prefix('!').map_or((false, line), |s| (true, s));
        let line = line.trim();
        if line.is_empty() {
            return Err(invalid(format!(
                "unsupported pattern at line {}",
                line_number + 1
            )));
        }
        let line = clean_pattern(line);
        if line.is_empty() {
            continue;
        }
        if patterns.len() == MAX_PATTERNS {
            return Err(invalid("too many patterns"));
        }
        let source = compile_pattern(&line)
            .map_err(|()| invalid(format!("unsupported pattern at line {}", line_number + 1)))?;
        let expression = Regex::new(&source)
            .map_err(|_| invalid(format!("unsupported pattern at line {}", line_number + 1)))?;
        patterns.push(Pattern {
            expression,
            negated,
        });
    }
    Ok(patterns)
}

/// Compiled Docker build-context ignore patterns in declaration order.
///
/// Paths must be slash-separated and relative to the watched root. Unsupported
/// pattern syntax is rejected, following the engine's bounded dockerignore subset.
#[derive(Debug)]
pub struct IgnoreMatcher {
    inner: BuildIgnore,
}
impl IgnoreMatcher {
    /// Compile newline-separated ignore patterns.
    ///
    /// # Errors
    /// Returns an error for invalid patterns or limits exceeded.
    pub fn parse(text: &str) -> Result<Self, ImageTransferError> {
        Ok(Self {
            inner: BuildIgnore {
                patterns: parse_patterns(text)?,
                selected: String::new(),
            },
        })
    }
    /// Whether the ordered rules exclude this relative path.
    #[must_use]
    pub fn is_ignored(&self, path: &str) -> bool {
        self.inner.excluded(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{IgnoreMatcher, clean_pattern, compile_pattern};

    #[test]
    fn public_matcher_preserves_negation_order_and_rejects_bad_patterns() {
        let matcher = IgnoreMatcher::parse("*.tmp\n!important.tmp\n").unwrap();
        assert!(matcher.is_ignored("drop.tmp"));
        assert!(!matcher.is_ignored("important.tmp"));
        assert!(IgnoreMatcher::parse("[").is_err());
    }
    use regex::Regex;

    #[test]
    fn moby_matcher_cases() {
        // Representative cases from moby/patternmatcher's TestMatches and
        // TestMatch, including its special leading-** suffix optimization.
        for (pattern, path, expected) in [
            ("a[b-d]e", "ace", true),
            ("a[b-d]e", "aae", false),
            ("a[^b-d]e", "aze", true),
            ("a\\*b", "a*b", true),
            ("a\\*b", "axb", false),
            ("[\\]a]", "]", true),
            ("[\\-]", "-", true),
            ("[a-ζ]*", "α", true),
            ("**file", "prefixfile", true),
            ("**file", "dir/file", true),
            ("a**/*.txt", "a/dir/file.txt", true),
            ("a**/*.txt", "a/file.txt", true),
            ("**/file*", "dir/dir/file.txt", true),
        ] {
            let expression = Regex::new(&compile_pattern(pattern).unwrap()).unwrap();
            assert_eq!(expression.is_match(path), expected, "{pattern:?} {path:?}");
        }
        for pattern in ["[", "[x-]", "[-]", "[a-b-c]", "[z-a]", "\\"] {
            assert!(compile_pattern(pattern).is_err(), "{pattern:?}");
        }
    }

    #[test]
    fn ignore_reader_path_cleaning() {
        for (input, expected) in [
            ("./target", "target"),
            ("foo//bar", "foo/bar"),
            ("foo/../target", "target"),
            ("/../target", "target"),
            ("../target", "../target"),
        ] {
            assert_eq!(clean_pattern(input), expected);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_separators_are_cleaned_before_matching() {
        let pattern = clean_pattern(r"other\..\secrets\*");
        assert_eq!(pattern, "secrets/*");
        let expression = Regex::new(&compile_pattern(&pattern).unwrap()).unwrap();
        assert!(expression.is_match("secrets/token"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_backslash_remains_an_escape() {
        let pattern = clean_pattern(r"secrets\*");
        assert_eq!(pattern, r"secrets\*");
        let expression = Regex::new(&compile_pattern(&pattern).unwrap()).unwrap();
        assert!(expression.is_match("secrets*"));
        assert!(!expression.is_match("secrets/token"));
    }
}
