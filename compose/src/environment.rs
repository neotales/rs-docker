//! The ordered, platform-aware environment that dotenv and value resolution run
//! against.
//!
//! `neotales-env` publishes the platform rules this module uses but no longer
//! publishes an environment map, so the model lives here. Its twin is
//! `neotales-docker-bake`'s `environment` module: the two crates must not
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
