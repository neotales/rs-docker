//! `build.ssh` forwards are retained, merged, and rendered without resolution.
//!
//! The model keeps the declared spelling. `default` names the caller's ambient
//! agent and a path may be relative to the project, so neither can be resolved
//! by a daemon-free model; the values are carried to whoever runs the build.
use neotales_docker_compose::{
    ComposeConfigRenderer, ComposeFileReadError, ComposeFileResolver, ComposeProject,
    ComposeProjectOptions, ComposeResolvedFile, InterpolationValues, MergePolicy,
};

struct NoExternalFiles;
impl ComposeFileResolver for NoExternalFiles {
    fn read(&self, _: &str, _: &str) -> Result<ComposeResolvedFile, ComposeFileReadError> {
        Err(ComposeFileReadError::Refused)
    }
    fn glob(&self, _: &str, _: &str) -> Result<Vec<ComposeResolvedFile>, ComposeFileReadError> {
        Err(ComposeFileReadError::Refused)
    }
}

fn parse(source: &str) -> ComposeProject {
    ComposeProject::parse_yaml(
        source,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .expect("project")
}

#[test]
fn build_ssh_entries_keep_their_declared_spelling() {
    let source = "services:\n  app:\n    image: app:test\n    build:\n      context: .\n      ssh:\n        - default\n        - deploy=/run/agent.sock\n";
    let project = parse(source);
    let build = project.services["app"].build.as_ref().expect("build");
    assert_eq!(build.ssh, ["default", "deploy=/run/agent.sock"]);

    // The model round-trips through its serialized form unchanged.
    let json = serde_json::to_value(build).expect("build JSON");
    assert_eq!(json["ssh"][1], "deploy=/run/agent.sock");
    let restored: neotales_docker_compose::ComposeBuild =
        serde_json::from_value(json).expect("build from JSON");
    assert_eq!(restored.ssh, build.ssh);

    // Rendered YAML is the declared spelling, so it parses back to the model.
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    assert!(rendered.contains("- deploy=/run/agent.sock"), "{rendered}");
    let roundtrip = parse(&rendered);
    assert_eq!(
        roundtrip.services["app"].build.as_ref().unwrap().ssh,
        build.ssh
    );
}

#[test]
fn a_single_ssh_entry_may_be_spelled_without_a_list() {
    let project = parse(
        "services:\n  app:\n    image: app:test\n    build:\n      context: .\n      ssh: default\n",
    );
    let build = project.services["app"].build.as_ref().expect("build");
    assert_eq!(build.ssh, ["default"]);
    // Rendering always emits the list spelling, which is what a reader of a
    // normalized document expects.
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    let roundtrip = parse(&rendered);
    assert_eq!(
        roundtrip.services["app"].build.as_ref().unwrap().ssh,
        ["default"]
    );
}

#[test]
fn ssh_entries_merge_across_files_in_declaration_order() {
    let base = "services:\n  app:\n    image: app:test\n    build:\n      context: .\n      ssh: [default]\n";
    let over = "services:\n  app:\n    build:\n      ssh: [deploy=/run/agent.sock]\n";
    let project = ComposeProject::parse_sources(
        &[(base, "base.yaml"), (over, "over.yaml")],
        &InterpolationValues::new(),
        ComposeProjectOptions {
            merge: MergePolicy::MergeServices,
            ..ComposeProjectOptions::default()
        },
    )
    .expect("merged project");
    assert_eq!(
        project.services["app"].build.as_ref().unwrap().ssh,
        ["default", "deploy=/run/agent.sock"]
    );
}

#[test]
fn ssh_entries_survive_extends() {
    let source = "services:\n  base:\n    image: app:test\n    build:\n      context: .\n      ssh: [default]\n  app:\n    extends: {service: base}\n    build:\n      ssh: [deploy=/run/agent.sock]\n";
    let project = ComposeProject::parse_sources_with_resolver(
        &[(source, "compose.yaml")],
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
        &NoExternalFiles,
    )
    .expect("project");
    assert_eq!(
        project.services["app"].build.as_ref().unwrap().ssh,
        ["default", "deploy=/run/agent.sock"]
    );
}

#[test]
fn an_empty_ssh_entry_is_refused() {
    let error = ComposeProject::parse_yaml(
        "services:\n  app:\n    image: app:test\n    build:\n      context: .\n      ssh: [\"\"]\n",
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .expect_err("an empty entry must be refused");
    assert!(format!("{error:?}").contains("build.ssh"), "{error:?}");
}

#[test]
fn a_mapping_ssh_entry_is_refused() {
    let error = ComposeProject::parse_yaml(
        "services:\n  app:\n    image: app:test\n    build:\n      context: .\n      ssh:\n        - {id: deploy}\n",
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .expect_err("a mapping entry must be refused");
    assert!(format!("{error:?}").contains("ssh"), "{error:?}");
}
