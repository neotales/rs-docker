//! Opt-in, bounded Go-template rendering for explicit Bake sources.

use std::{collections::BTreeMap, fmt, sync::Arc};

use crate::environment::Environment;
pub use neotales_gotmpl::{Error as TemplateError, ParseOptions, RenderOptions};
use neotales_gotmpl::{Template, Value as EngineValue};
pub use neotales_sprig::Value;

use crate::VariableValues;

/// The engine-to-helper value bridge and the safe helper set.
///
/// `neotales-gotmpl` ships no helper library, and `neotales-sprig` does not
/// depend on an engine, so the two value types are distinct on purpose and
/// joining them is the caller's job. This module is that join: the nine-variant
/// conversion in each direction, and one function map that registers the whole
/// safe helper set against it.
///
/// It lives here rather than in a shared crate because a crate holding it would
/// be a dependency of both this crate and `neotales-docker-compose`, and an
/// unpublished crate in that position would stop either from being published.
///
/// The environment `env` and `expandenv` read is the `.env` namespace of the
/// values map, not the process environment, so the same source and the same
/// values render the same bytes on a developer machine and in a pipeline.
mod sprig_helpers {
    use std::{collections::BTreeMap, sync::Arc};

    use neotales_gotmpl::{Error, FuncMap, Value as EngineValue};
    use neotales_sprig::{Context, Value as HelperValue};

    /// Converts one caller value into the engine's value of the same shape.
    pub(super) fn to_engine(value: &HelperValue) -> EngineValue {
        match value {
            HelperValue::String(value) => EngineValue::String(value.clone()),
            HelperValue::Bool(value) => EngineValue::Bool(*value),
            HelperValue::Number(value) => EngineValue::Number(*value),
            HelperValue::Float(value) => EngineValue::Float(*value),
            HelperValue::Null => EngineValue::Null,
            HelperValue::List(values) => EngineValue::List(values.iter().map(to_engine).collect()),
            HelperValue::Map(values) => EngineValue::Map(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), to_engine(value)))
                    .collect(),
            ),
            HelperValue::Object { display, members } => EngineValue::Object {
                display: display.clone(),
                members: members
                    .iter()
                    .map(|(key, value)| (key.clone(), to_engine(value)))
                    .collect(),
            },
            HelperValue::Method { helper, receiver } => EngineValue::Method {
                helper: helper.clone(),
                receiver: Box::new(to_engine(receiver)),
            },
        }
    }

    /// Converts one helper result back into the engine's value type.
    pub(super) fn from_engine(value: EngineValue) -> HelperValue {
        match value {
            EngineValue::String(value) => HelperValue::String(value),
            EngineValue::Bool(value) => HelperValue::Bool(value),
            EngineValue::Number(value) => HelperValue::Number(value),
            EngineValue::Float(value) => HelperValue::Float(value),
            EngineValue::Null => HelperValue::Null,
            EngineValue::List(values) => {
                HelperValue::List(values.into_iter().map(from_engine).collect())
            }
            EngineValue::Map(values) => HelperValue::Map(
                values
                    .into_iter()
                    .map(|(key, value)| (key, from_engine(value)))
                    .collect(),
            ),
            EngineValue::Object { display, members } => HelperValue::Object {
                display,
                members: members
                    .into_iter()
                    .map(|(key, value)| (key, from_engine(value)))
                    .collect(),
            },
            EngineValue::Method { helper, receiver } => HelperValue::Method {
                helper,
                receiver: Box::new(from_engine(*receiver)),
            },
        }
    }

    /// Builds a function map holding every safe helper, reading `environment`.
    pub(super) fn functions(environment: Arc<BTreeMap<String, String>>) -> FuncMap {
        let mut functions = FuncMap::new();
        functions.register_names(&neotales_sprig::helper_names(), move |name, arguments| {
            // Which helpers want their arguments already rendered is a property
            // of the helper set, so it is asked here once per call rather than
            // guessed from the name.
            let rendered_arguments = neotales_sprig::takes_rendered_strings(name);
            let arguments: Vec<HelperValue> = arguments
                .iter()
                .map(|argument| {
                    let value = from_engine(argument.clone());
                    if rendered_arguments {
                        HelperValue::String(value.render())
                    } else {
                        value
                    }
                })
                .collect();
            let context = Context::with_environment(environment.as_ref());
            neotales_sprig::call_with(name, &arguments, &context)
                .map(|value| to_engine(&value))
                .map_err(|error| Error::from(error.to_string()))
        });
        functions
    }

    /// Reads the template's own environment out of the `.env` namespace.
    ///
    /// A template with no `.env` namespace has an empty environment rather than
    /// none, so `env` reports an unset name as the empty string, which is what
    /// Go's sprig `env` does.
    pub(super) fn environment(values: &BTreeMap<String, HelperValue>) -> BTreeMap<String, String> {
        let mut environment = BTreeMap::new();
        if let Some(HelperValue::Map(entries)) = values.get("env") {
            for (name, value) in entries {
                environment.insert(name.clone(), value.render());
            }
        }
        environment
    }
}

/// Bounds and cooperative cancellation for one Bake template render.
///
/// The parse and render limits are the stable public contracts from
/// `neotales-gotmpl`. A cancellation callback is observed during both parsing
/// and rendering.
#[derive(Clone, Copy, Default)]
pub struct TemplateOptions<'a> {
    /// Bounds applied while parsing the template source.
    pub parse: ParseOptions,
    /// Bounds and cancellation applied while rendering explicit values.
    pub render: RenderOptions<'a>,
}

impl<'a> TemplateOptions<'a> {
    /// Creates the default finite parse and render limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns these options with different parse limits.
    #[must_use]
    pub fn with_parse_options(mut self, options: ParseOptions) -> Self {
        self.parse = options;
        self
    }

    /// Returns these options with different render limits and cancellation.
    #[must_use]
    pub fn with_render_options(mut self, options: RenderOptions<'a>) -> Self {
        self.render = options;
        self
    }

    /// Returns these options with one cancellation callback for both phases.
    #[must_use]
    pub fn with_cancellation(mut self, callback: &'a dyn Fn() -> bool) -> Self {
        self.render.is_cancelled = Some(callback);
        self
    }
}

impl fmt::Debug for TemplateOptions<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemplateOptions")
            .field("parse", &self.parse)
            .field("render", &self.render)
            .finish()
    }
}

/// Explicit values accepted by the Bake template adapter.
///
/// The environment implementations are the preferred path because they retain
/// order and platform-aware key identity. The typed-map implementation keeps
/// the pre-RD-009 template API source-compatible for callers that need helper
/// values which are not environment strings.
pub trait TemplateValues {
    /// Converts this value set into the deterministic typed template context.
    fn template_values(&self) -> BTreeMap<String, Value>;
}

impl TemplateValues for VariableValues {
    fn template_values(&self) -> BTreeMap<String, Value> {
        self.iter()
            .map(|(name, value)| (name.to_owned(), Value::String(value.to_owned())))
            .collect()
    }
}

impl TemplateValues for Environment {
    fn template_values(&self) -> BTreeMap<String, Value> {
        self.as_map()
            .iter()
            .map(|(name, value)| (name.to_owned(), Value::String(value.to_owned())))
            .collect()
    }
}

impl TemplateValues for BTreeMap<String, Value> {
    fn template_values(&self) -> BTreeMap<String, Value> {
        self.clone()
    }
}

/// Renders one explicit Bake source with the ordered variable model.
///
/// The same [`VariableValues`] instance can be passed to
/// [`crate::normalize_with_values`] or produced by the explicit dotenv loader.
/// Sources without a Go-template opening delimiter are returned unchanged and
/// do not invoke parsing, rendering, cancellation, or value conversion.
/// Template errors are returned directly from `neotales-gotmpl`; rendered
/// values are never added to diagnostics.
///
/// # Examples
///
/// ```
/// use neotales_docker_bake::{TemplateOptions, VariableValues, render_template};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let values = VariableValues::from_pairs([("name", "app")]);
/// let rendered = render_template("image: {{ .name }}", &values, &TemplateOptions::default())?;
/// assert_eq!(rendered, "image: app");
///
/// let rejected = render_template("{{", &VariableValues::new(), &TemplateOptions::default());
/// assert!(rejected.is_err());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a parse, safe-helper, cancellation, or resource-limit error.
pub fn render_template<V>(
    source: &str,
    values: &V,
    options: &TemplateOptions<'_>,
) -> Result<String, TemplateError>
where
    V: TemplateValues + ?Sized,
{
    if source.len() > options.parse.max_source_length {
        return Err(TemplateError::ResourceLimitExceeded);
    }
    if !source.contains("{{") {
        return Ok(source.to_owned());
    }

    let template = if let Some(is_cancelled) = options.render.is_cancelled {
        Template::parse_with_cancellation(source, options.parse, is_cancelled)?
    } else {
        Template::parse_with_options(source, options.parse)?
    };
    let values = values.template_values();
    let environment = Arc::new(sprig_helpers::environment(&values));
    let template = template.with_funcs(sprig_helpers::functions(environment));
    let values: BTreeMap<String, EngineValue> = values
        .iter()
        .map(|(name, value)| (name.clone(), sprig_helpers::to_engine(value)))
        .collect();
    template.render_typed_with_options(&values, options.render)
}
