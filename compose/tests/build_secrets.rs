//! Build-secret references retain their source and merge without reading it.
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

#[test]
fn external_cache_types_merge_and_render_like_compose_config() {
    // Docker Compose 5.6.1 `config` preserves these entries verbatim.
    let base = "services:\n  app:\n    image: app:test\n    build:\n      cache_from: ['type=local,src=cache', 'type=gha,scope=app']\n      cache_to: ['type=local,dest=cache', 'type=gha,scope=app']\n";
    let over = "services:\n  app:\n    build:\n      cache_from: ['type=s3,bucket=example,region=us-east-1']\n      cache_to: ['type=s3,bucket=example,region=us-east-1']\n";
    let project = ComposeProject::parse_sources(
        &[(base, "base.yaml"), (over, "over.yaml")],
        &InterpolationValues::new(),
        ComposeProjectOptions {
            merge: MergePolicy::MergeServices,
            ..ComposeProjectOptions::default()
        },
    )
    .unwrap();
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    let parsed = ComposeProject::parse_yaml(
        &rendered,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .unwrap();
    let build = parsed.services["app"].build.as_ref().unwrap();
    assert_eq!(
        build.cache_from,
        [
            "type=local,src=cache",
            "type=gha,scope=app",
            "type=s3,bucket=example,region=us-east-1"
        ]
    );
    assert_eq!(
        build.cache_to,
        [
            "type=local,dest=cache",
            "type=gha,scope=app",
            "type=s3,bucket=example,region=us-east-1"
        ]
    );
}

#[test]
fn cache_destinations_merge_and_render() {
    let base = "services:\n  app:\n    image: app:test\n    build:\n      cache_from: [app:one]\n      cache_to: ['type=registry,ref=app:one']\n";
    let over = "services:\n  app:\n    build:\n      cache_from: [app:two]\n      cache_to: ['type=registry,ref=app:two']\n";
    let project = ComposeProject::parse_sources(
        &[(base, "base.yaml"), (over, "over.yaml")],
        &InterpolationValues::new(),
        ComposeProjectOptions {
            merge: MergePolicy::MergeServices,
            ..ComposeProjectOptions::default()
        },
    )
    .unwrap();
    let expected = ["type=registry,ref=app:one", "type=registry,ref=app:two"];
    assert_eq!(
        project.services["app"].build.as_ref().unwrap().cache_to,
        expected
    );
    assert_eq!(
        project.services["app"].build.as_ref().unwrap().cache_from,
        ["app:one", "app:two"]
    );
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    let parsed = ComposeProject::parse_yaml(
        &rendered,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .unwrap();
    assert_eq!(
        parsed.services["app"].build.as_ref().unwrap().cache_to,
        expected
    );
    assert_eq!(
        parsed.services["app"].build.as_ref().unwrap().cache_from,
        ["app:one", "app:two"]
    );
}

#[test]
fn cache_lists_survive_extends() {
    let source = "services:\n  base:\n    image: app:test\n    build:\n      cache_from: [app:one]\n      cache_to: [app:one]\n  app:\n    extends: {service: base}\n    build:\n      cache_from: [app:two]\n      cache_to: [app:two]\n";
    let project = ComposeProject::parse_sources_with_resolver(
        &[(source, "compose.yaml")],
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
        &NoExternalFiles,
    )
    .unwrap();
    let build = project.services["app"].build.as_ref().unwrap();
    assert_eq!(build.cache_from, ["app:one", "app:two"]);
    assert_eq!(build.cache_to, ["app:one", "app:two"]);
}

#[test]
fn build_secret_grants_round_trip_without_values() {
    let source = r#"
services:
  app:
    image: example:test
    build:
      context: .
      secrets:
        - first
        - source: second
          target: token
          uid: "1000"
          gid: "1001"
          mode: "0440"
secrets:
  first:
    file: first.txt
  second:
    environment: TEST_TOKEN
"#;
    let project = ComposeProject::parse_yaml(
        source,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .unwrap();
    let build = project.services["app"].build.as_ref().unwrap();
    assert_eq!(build.secrets.len(), 2);
    assert_eq!(build.secrets[0].source, "first");
    assert_eq!(build.secrets[1].target.as_deref(), Some("token"));
    assert_eq!(build.secrets[1].mode.as_deref(), Some("0440"));
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    assert!(rendered.contains("source: first"));
    assert!(rendered.contains("source: second"));
    assert!(rendered.contains("target: token"));
    assert!(rendered.contains("environment: TEST_TOKEN"));
    let roundtrip = ComposeProject::parse_yaml(
        &rendered,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .unwrap();
    assert_eq!(
        roundtrip.services["app"].build.as_ref().unwrap().secrets,
        build.secrets
    );
}

#[test]
fn build_secret_and_build_fields_merge() {
    let base = "services:\n  app:\n    image: example:test\n    build:\n      context: sub\n      dockerfile: nested/File\n      args: {A: base}\n      secrets: [first]\nsecrets:\n  first: {file: one.txt}\n";
    let over = "services:\n  app:\n    build:\n      target: release\n      args: {B: extra}\n      secrets:\n        - source: second\n          target: token\nsecrets:\n  second: {environment: TOKEN}\n";
    let options = ComposeProjectOptions {
        merge: MergePolicy::MergeServices,
        ..ComposeProjectOptions::default()
    };
    let project = ComposeProject::parse_sources(
        &[(base, "base.yaml"), (over, "over.yaml")],
        &InterpolationValues::new(),
        options,
    )
    .unwrap();
    let build = project.services["app"].build.as_ref().unwrap();
    assert_eq!(build.context, "sub");
    assert_eq!(build.dockerfile.as_deref(), Some("nested/File"));
    assert_eq!(build.target.as_deref(), Some("release"));
    assert_eq!(build.arguments["A"], "base");
    assert_eq!(build.arguments["B"], "extra");
    assert_eq!(build.secrets.len(), 2);
}

#[test]
fn invalid_grants_are_rejected_by_field() {
    for source in [
        "services:\n  app:\n    build:\n      secrets: [missing]\n",
        "services:\n  app:\n    build:\n      secrets:\n        - {source: token, unexpected: x}\nsecrets:\n  token: {file: a}\n",
    ] {
        assert!(
            ComposeProject::parse_yaml(
                source,
                "compose.yaml",
                &InterpolationValues::new(),
                ComposeProjectOptions::default()
            )
            .is_err()
        );
    }
}

#[test]
fn unknown_build_and_secret_fields_name_the_field() {
    for (source, field) in [
        (
            "services:\n  app:\n    image: alpine\n    build: {unrecognized: true}\n",
            "unrecognized",
        ),
        (
            "services:\n  app:\n    image: alpine\n    build:\n      secrets:\n        - {source: token, unknown_key: x}\nsecrets:\n  token: {file: token.txt}\n",
            "unknown_key",
        ),
    ] {
        let error = ComposeProject::parse_yaml(
            source,
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .unwrap_err();
        assert!(format!("{error:?}").contains(field));
    }
}

#[test]
fn numeric_octal_mode_matches_compose_rendering() {
    let source = "services:\n  app:\n    image: alpine\n    build:\n      secrets:\n        - source: token\n          mode: 0440\nsecrets:\n  token: {file: token.txt}\n";
    let project = ComposeProject::parse_yaml(
        source,
        "compose.yaml",
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
    )
    .unwrap();
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    assert!(rendered.contains("0440"), "{rendered}");
}

#[test]
fn extends_merges_build_secrets_without_losing_context_or_args() {
    let source = "services:\n  base:\n    image: alpine\n    build:\n      context: sub\n      dockerfile: Dockerfile.alt\n      args: {A: base}\n      secrets: [one]\n  app:\n    extends: {service: base}\n    build:\n      target: final\n      secrets: [two]\nsecrets:\n  one: {file: one.txt}\n  two: {environment: TOKEN}\n";
    let project = ComposeProject::parse_sources_with_resolver(
        &[(source, "/project/compose.yaml")],
        &InterpolationValues::new(),
        ComposeProjectOptions::default(),
        &NoExternalFiles,
    )
    .unwrap();
    let build = project.services["app"].build.as_ref().unwrap();
    assert_eq!(build.context, "sub");
    assert_eq!(build.dockerfile.as_deref(), Some("Dockerfile.alt"));
    assert_eq!(build.target.as_deref(), Some("final"));
    assert_eq!(build.arguments["A"], "base");
    assert_eq!(
        build
            .secrets
            .iter()
            .map(|v| v.source.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
}
