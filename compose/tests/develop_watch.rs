//! Development watch declarations survive parsing and validation.

use neotales_docker_compose::{
    ComposeConfigRenderer, ComposeProject, ComposeProjectOptions, ComposeWatchAction,
    InterpolationValues,
};

fn parse(source: &str) -> Result<ComposeProject, neotales_docker_compose::ComposeError> {
    ComposeProject::parse_yaml(
        source,
        "compose.yaml",
        &InterpolationValues::from_pairs([("SRC", "source"), ("DEST", "/app")]),
        ComposeProjectOptions::default(),
    )
}

#[test]
fn parses_short_and_long_watch_rules_with_interpolation() {
    let project = parse(
        "services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: ${SRC}\n          target: /app\n        - path: ${SRC}/files\n          target: ${DEST}\n          ignore: ['*.tmp', '!keep.tmp']\n          action: sync+restart\n        - path: build\n          action: rebuild\n",
    ).unwrap();
    let rules = &project.services["web"].develop.as_ref().unwrap().watch;
    assert_eq!(rules.len(), 3);
    assert!(rules[0].path.ends_with("/source"));
    assert_eq!(rules[0].action, ComposeWatchAction::Sync);
    assert!(rules[1].path.ends_with("/source/files"));
    assert_eq!(rules[1].target.as_deref(), Some("/app"));
    assert_eq!(rules[1].ignore, ["*.tmp", "!keep.tmp"]);
    assert_eq!(rules[1].action, ComposeWatchAction::SyncRestart);
    assert_eq!(rules[2].action, ComposeWatchAction::Rebuild);
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    let roundtrip = parse(&rendered).unwrap();
    assert_eq!(
        roundtrip.services["web"].develop,
        project.services["web"].develop
    );
}

#[test]
fn refuses_unknown_watch_fields_and_actions_by_name() {
    for (declaration, expected) in [
        ("action: explode", "explode"),
        ("initial_sync: true", "initial_sync"),
    ] {
        let source = format!(
            "services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          {declaration}\n"
        );
        let error = parse(&source).unwrap_err();
        assert!(error.message().contains(expected), "{error}");
    }
    let error = parse("services:\n  web:\n    image: alpine\n    develop:\n      mystery: true\n")
        .unwrap_err();
    assert!(error.message().contains("mystery"));
}

#[test]
fn absent_develop_is_unchanged() {
    let project = parse("services:\n  web:\n    image: alpine\n").unwrap();
    assert!(project.services["web"].develop.is_none());
    assert!(!ComposeConfigRenderer::render_yaml(&project).contains("develop:"));
}

#[test]
fn exec_forms_and_required_path_are_checked() {
    for (command, expected) in [
        ("echo hello", vec!["echo", "hello"]),
        ("[echo, hello]", vec!["echo", "hello"]),
    ] {
        let source = format!(
            "services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          action: sync+exec\n          target: /app\n          exec:\n            command: {command}\n"
        );
        let project = parse(&source).unwrap();
        let rule = &project.services["web"].develop.as_ref().unwrap().watch[0];
        assert_eq!(rule.action, ComposeWatchAction::SyncExec);
        assert_eq!(rule.exec.as_ref().unwrap(), &expected);
        assert_eq!(
            parse(&ComposeConfigRenderer::render_yaml(&project))
                .unwrap()
                .services["web"]
                .develop,
            project.services["web"].develop
        );
    }
    let error = parse("services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - action: sync\n").unwrap_err();
    assert!(error.message().contains("path"));
}

#[test]
fn develop_survives_overrides_and_extends() {
    use neotales_docker_compose::MergePolicy;
    let base = "services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          action: rebuild\n";
    let override_source = "services:\n  web:\n    hostname: example\n";
    let options = ComposeProjectOptions {
        merge: MergePolicy::MergeServices,
        ..ComposeProjectOptions::default()
    };
    let project = ComposeProject::parse_sources(
        &[(base, "base.yaml"), (override_source, "override.yaml")],
        &InterpolationValues::new(),
        options,
    )
    .unwrap();
    assert_eq!(
        project.services["web"].develop.as_ref().unwrap().watch[0].path,
        std::env::current_dir()
            .unwrap()
            .join("src")
            .to_str()
            .unwrap()
    );
    let project = parse("services:\n  base:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          action: rebuild\n  child:\n    extends: {service: base}\n").unwrap();
    assert_eq!(
        project.services["child"].develop,
        project.services["base"].develop
    );
}

#[test]
fn sync_actions_require_target_but_rebuild_does_not() {
    for action in ["sync", "sync+restart", "sync+exec"] {
        let source = format!(
            "services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          action: {action}\n"
        );
        let error = parse(&source).unwrap_err();
        assert!(error.path().contains("watch[0].target"), "{error}");
    }
    assert!(parse("services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          action: rebuild\n").is_ok());
}

#[test]
fn watch_paths_render_absolute_and_exec_string_as_argv() {
    let project = parse("services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          action: sync+exec\n          target: /app\n          exec:\n            command: echo hello\n").unwrap();
    let rendered = ComposeConfigRenderer::render_yaml(&project);
    let path = std::env::current_dir().unwrap().join("src");
    assert!(
        rendered.contains(&format!("path: {}", path.display())),
        "{rendered}"
    );
    assert!(
        rendered.contains("command:\n              - echo\n              - hello"),
        "{rendered}"
    );
}

#[test]
fn sync_exec_requires_a_command() {
    for declaration in [
        "",
        "          exec: {}\n",
        "          exec:\n            command: []\n",
    ] {
        let source = format!(
            "services:\n  web:\n    image: alpine\n    develop:\n      watch:\n        - path: src\n          action: sync+exec\n          target: /app\n{declaration}"
        );
        let error = parse(&source).unwrap_err();
        assert!(error.path().contains("watch[0].exec.command"), "{error}");
    }
}
