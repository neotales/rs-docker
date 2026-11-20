//! The ordered, platform-aware environment that dotenv and value resolution run
//! against.
//!
//! `neotales-env` publishes the platform rules this module uses but no longer
//! publishes an environment map, so the model lives here. Its twin is
//! `neotales-docker-compose`'s `environment` module: the two crates must not
//! depend on each other, and a shared crate holding this type would have to be
//! published for either to be publishable. Keep the two copies in step.

use indexmap::IndexMap;
pub use neotales_env::Platform;

/// An insertion-ordered environment which preserves the first selected key spelling.
///
/// On Windows, keys are compared ASCII case-insensitively and the spelling first
/// inserted wins, so `Path` and `PATH` are one entry. No constructor reads the
/// process environment: the values are the caller's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Environment {
    platform: Platform,
    values: IndexMap<String, String>,
}

impl Environment {
    /// Creates an empty environment using the given platform's rules.
    #[must_use]
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            values: IndexMap::new(),
        }
    }

    /// Returns the platform rules used for key comparison.
    #[must_use]
    pub fn platform(&self) -> Platform {
        self.platform
    }

    /// Returns the value stored under `key`, or `None` when it is not set.
    ///
    /// The lookup follows the platform's case rules, so on Windows `path` finds
    /// an entry stored as `Path`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(existing, _)| keys_equal(self.platform, existing, key))
            .map(|(_, value)| value.as_str())
    }

    /// Sets `key` to `value`, returning whatever it held before.
    ///
    /// An existing entry keeps the spelling it was first inserted with, so this
    /// updates in place rather than adding a second entry under a differently
    /// capitalised name.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        let key = key.into();
        let value = value.into();
        if let Some(existing) = self
            .values
            .keys()
            .find(|existing| keys_equal(self.platform, existing, &key))
            .cloned()
        {
            return self.values.insert(existing, value);
        }
        self.values.insert(key, value)
    }

    /// Removes `key`, returning its value when it was set.
    ///
    /// This is `shift_remove` rather than `swap_remove`, so the order of the
    /// remaining entries is preserved.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        let existing = self
            .values
            .keys()
            .find(|existing| keys_equal(self.platform, existing, key))
            .cloned()?;
        self.values.shift_remove(&existing)
    }

    /// Returns the entries in the order they were first inserted.
    #[must_use]
    pub fn as_map(&self) -> &IndexMap<String, String> {
        &self.values
    }
}

/// Expands `$NAME` and `${NAME}` using explicitly supplied values. Unset names are empty.
#[must_use]
pub(crate) fn interpolate(value: &str, environment: &Environment) -> String {
    interpolate_with(value, |name| environment.get(name))
}

/// Expands `$NAME` and `${NAME}` using an explicit lookup function.
///
/// A name is a run of ASCII letters, digits and underscores, and the character
/// that ends it is not part of it. The unbraced form therefore keeps the `/` in
/// `$HOME/bin` rather than swallowing it into the name.
#[must_use]
pub(crate) fn interpolate_with<'a>(
    value: &str,
    mut lookup: impl FnMut(&str) -> Option<&'a str>,
) -> String {
    let mut output = String::with_capacity(value.len());
    // `rest` is the part of `value` not yet copied, and it is always sliced
    // rather than iterated, so the character that ends a name is still at the
    // front of `rest` when the next iteration looks at it.
    let mut rest = value;
    while let Some(dollar) = rest.find('$') {
        output.push_str(&rest[..dollar]);
        rest = &rest[dollar + 1..];
        if let Some(braced) = rest.strip_prefix('{') {
            // A `${NAME` with no closing brace takes the rest of the value as
            // its name, which is what the braced form has always done.
            let end = braced.find('}').unwrap_or(braced.len());
            output.push_str(lookup(&braced[..end]).unwrap_or(""));
            // The closing brace is consumed here rather than by a `take_while`
            // that had to eat it to stop. `braced[end]` is the brace, so
            // `end + 1` is the next character boundary.
            rest = if end < braced.len() {
                &braced[end + 1..]
            } else {
                ""
            };
            continue;
        }
        let end = name_end(rest);
        if end == 0 {
            // A `$` with no name after it is literal, and whatever follows it
            // has not been looked at yet.
            output.push('$');
        } else {
            output.push_str(lookup(&rest[..end]).unwrap_or(""));
            rest = &rest[end..];
        }
    }
    output.push_str(rest);
    output
}

/// Compares two environment keys under `platform`'s rules.
///
/// `Platform` keeps its own comparison private, and these are the rules it
/// documents: Windows folds ASCII case, every other platform compares bytes.
fn keys_equal(platform: Platform, left: &str, right: &str) -> bool {
    match platform {
        Platform::Unix => left == right,
        Platform::Windows => left.eq_ignore_ascii_case(right),
    }
}

/// Returns the byte length of the variable name at the start of `value`.
///
/// Zero means there is no name there, so the caller emits a literal `$` rather
/// than a lookup. The name characters are the set the unbraced form has always
/// accepted; only the handling of the character after them has changed.
fn name_end(value: &str) -> usize {
    value
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(value.len())
}
