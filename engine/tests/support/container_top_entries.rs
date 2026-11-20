//! `GET /containers/{id}/top` documents shared by the owned and fallback
//! routing suites.
//!
//! Both suites must send the *same* recorded answers through both transports,
//! or a difference in their results would be a difference in the fixture rather
//! than in the code. The Engine declares `Titles` and `Processes` optional and
//! the generated model carries both as `Option`, so the documents here cover
//! the two ways a member can be absent, the two ways it can be wrong, and one
//! member the projection does not model.

/// A process list in the shape Docker Engine answers.
pub(super) const TOP_BODY: &str =
    r#"{"Titles":["PID","CMD"],"Processes":[["1","sleep 60"],["7","sh"]]}"#;

/// Both optional members absent, which is an empty process table.
pub(super) const MISSING_MEMBERS_BODY: &str = "{}";

/// Both optional members present as `null`, which is also an empty process
/// table rather than a type error.
pub(super) const NULL_MEMBERS_BODY: &str = r#"{"Titles":null,"Processes":null}"#;

/// A member of the wrong JSON type: a string where the Engine declares an
/// array. Both decoders refuse it, in their own error class.
pub(super) const WRONG_TYPE_BODY: &str = r#"{"Titles":"PID"}"#;

/// A null row inside `Processes`, which neither decoder accepts as a process.
pub(super) const NULL_ROW_BODY: &str = r#"{"Titles":["PID"],"Processes":[null]}"#;

/// A member the repository projection does not model. Both decoders ignore it,
/// because neither response model denies unknown members.
pub(super) const EXTRA_MEMBER_BODY: &str = r#"{"Titles":["PID"],"Processes":[["1"]],"Extra":7}"#;
