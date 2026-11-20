#![allow(missing_docs)]
use neotales_docker::SwarmTask;
use serde_json::json;

#[test]
fn task_spec_has_one_authoritative_representation() {
    let mut task: SwarmTask = serde_json::from_value(json!({"ServiceID":"s","NodeID":"n","Slot":1,"Spec":{"ContainerSpec":{"Image":"img","Unknown":true}}})).unwrap();
    assert_eq!(task.additional.get("Spec"), task.spec.as_ref());
    task.additional
        .insert("Spec".into(), json!({"stale": true}));
    let text = serde_json::to_string(&task).unwrap();
    assert_eq!(text.matches("\"Spec\"").count(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["Spec"]["ContainerSpec"]["Unknown"],
        true
    );
}

#[test]
fn spec_removal_ignores_stale_mirror() {
    let mut task: SwarmTask = serde_json::from_value(
        json!({"ServiceID":"s","NodeID":"n","Slot":1,"Spec":{"unmodelled":42}}),
    )
    .unwrap();
    task.spec = None;
    task.additional
        .insert("Spec".into(), json!({"stale": true}));
    let value = serde_json::to_value(&task).unwrap();
    assert!(value.get("Spec").is_none());
}

#[test]
fn missing_and_null_spec_have_no_mirror() {
    for spec in [json!({}), json!({"Spec": null})] {
        let mut object = spec.as_object().unwrap().clone();
        object.insert("ServiceID".into(), json!("s"));
        object.insert("NodeID".into(), json!("n"));
        object.insert("Slot".into(), json!(1));
        let task: SwarmTask = serde_json::from_value(object.into()).unwrap();
        assert_eq!(task.spec, None);
        assert!(!task.additional.contains_key("Spec"));
        assert!(serde_json::to_value(task).unwrap().get("Spec").is_none());
    }
}

#[test]
fn canonical_edits_and_mirror_removal_round_trip() {
    let mut task: SwarmTask = serde_json::from_value(
        json!({"ServiceID":"s","NodeID":"n","Slot":1,"Spec":{"nested":{"unknown":[1,2]}}}),
    )
    .unwrap();
    task.spec.as_mut().unwrap()["nested"]["changed"] = json!(true);
    task.additional.remove("Spec");
    let serialized = serde_json::to_string(&task).unwrap();
    assert_eq!(serialized.matches("\"Spec\"").count(), 1);
    let round_trip: SwarmTask = serde_json::from_str(&serialized).unwrap();
    assert_eq!(
        round_trip.spec.unwrap()["nested"],
        json!({"unknown":[1,2],"changed":true})
    );
    assert_eq!(round_trip.additional["Spec"]["nested"]["changed"], true);
}
