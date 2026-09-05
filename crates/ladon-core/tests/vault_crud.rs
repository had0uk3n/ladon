use ladon_core::{
    ActivitySink, FieldName, LadonError, SecretField, SecretId, SecretRef, SensitiveBytes,
    TextHint, VaultPayload, VaultSession, create_vault,
};

#[derive(Default)]
struct CountingActivity {
    touches: usize,
}

impl ActivitySink for CountingActivity {
    fn secret_activity(&mut self) {
        self.touches += 1;
    }
}

fn field(name: &str, value: &[u8]) -> SecretField {
    SecretField::new(
        FieldName::parse(name).unwrap(),
        value.to_vec(),
        TextHint::Text,
    )
    .unwrap()
}

fn session() -> VaultSession<CountingActivity> {
    session_at_revision(0)
}

fn session_at_revision(revision: u64) -> VaultSession<CountingActivity> {
    let payload = VaultPayload::new(
        SecretId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
        revision,
        vec![],
    )
    .unwrap();
    let password = SensitiveBytes::new(b"correct horse battery staple".to_vec());
    let (unlocked, _) = create_vault(payload, &password).unwrap();
    VaultSession::new(unlocked, CountingActivity::default())
}

#[test]
fn revision_overflow_leaves_payload_unchanged() {
    let mut session = session_at_revision(u64::MAX);

    assert_eq!(
        session
            .add("first", vec![field("value", b"fake-one")])
            .unwrap_err(),
        LadonError::RevisionOverflow
    );
    assert!(session.list().is_empty());
    assert_eq!(session.activity().touches, 0);
}

#[test]
fn crud_preserves_ids_increments_revision_and_touches_only_secret_activity() {
    let mut session = session();
    let first_id = session
        .add("Cafe\u{301}", vec![field("value", b"fake-one")])
        .unwrap();
    let second_id = session
        .add(
            "second",
            vec![field("user", b"alice"), field("token", b"fake-two")],
        )
        .unwrap();

    assert_eq!(session.revision(), 2);
    assert_eq!(session.activity().touches, 2);
    let listed = session.list();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].name, "Café");
    assert_eq!(listed[1].field_names, vec!["user", "token"]);
    assert_eq!(
        session.activity().touches,
        2,
        "metadata listing is not secret use"
    );

    let value = session
        .with_field(
            &SecretRef::parse(&format!("id:{second_id}")).unwrap(),
            &FieldName::parse("token").unwrap(),
            |bytes| bytes.to_vec(),
        )
        .unwrap();
    assert_eq!(value, b"fake-two");
    assert_eq!(session.activity().touches, 3);

    session
        .rename(&SecretRef::parse("Café").unwrap(), "renamed")
        .unwrap();
    assert_eq!(session.list()[0].id, first_id);
    assert_eq!(session.list()[0].name, "renamed");
    assert_eq!(session.revision(), 3);

    session
        .replace_fields(
            &SecretRef::parse(&format!("id:{first_id}")).unwrap(),
            vec![field("value", b"replacement")],
        )
        .unwrap();
    assert_eq!(session.revision(), 4);

    session
        .delete(&SecretRef::parse("second").unwrap())
        .unwrap();
    assert_eq!(session.revision(), 5);
    assert_eq!(session.list().len(), 1);
}

#[test]
fn rejected_mutations_do_not_change_revision_or_activity() {
    let mut session = session();
    session
        .add("first", vec![field("value", b"fake-one")])
        .unwrap();
    session
        .add("second", vec![field("value", b"fake-two")])
        .unwrap();
    let revision = session.revision();
    let touches = session.activity().touches;

    assert_eq!(
        session
            .add("first", vec![field("value", b"fake-three")])
            .unwrap_err(),
        LadonError::DuplicateSecretName
    );
    assert_eq!(
        session
            .rename(&SecretRef::parse("second").unwrap(), "first")
            .unwrap_err(),
        LadonError::DuplicateSecretName
    );
    assert_eq!(
        session
            .delete(&SecretRef::parse("missing").unwrap())
            .unwrap_err(),
        LadonError::SecretNotFound
    );
    assert_eq!(session.revision(), revision);
    assert_eq!(session.activity().touches, touches);
}

#[test]
fn missing_fields_fail_without_exposing_another_value() {
    let mut session = session();
    session
        .add("first", vec![field("value", b"fake-one")])
        .unwrap();
    let touches = session.activity().touches;

    assert_eq!(
        session
            .with_field(
                &SecretRef::parse("first").unwrap(),
                &FieldName::parse("missing").unwrap(),
                |_| (),
            )
            .unwrap_err(),
        LadonError::FieldNotFound
    );
    assert_eq!(session.activity().touches, touches);
}

#[test]
fn whole_record_read_and_replace_preserve_id_and_increment_once() {
    let mut session = session();
    let id = session.add("before", vec![field("value", b"old")]).unwrap();
    let reference = SecretRef::parse(&format!("id:{id}")).unwrap();
    let before = session.revision();

    let observed = session
        .with_record(&reference, |record| {
            (record.id(), record.name().to_owned(), record.fields().len())
        })
        .unwrap();
    assert_eq!(observed, (id, "before".to_owned(), 1));

    let prepared = session
        .prepare_record_replacement(&reference, "after", vec![field("token", b"new")])
        .unwrap();
    assert_eq!(session.revision(), before);
    session.apply_record_replacement(prepared).unwrap();
    assert_eq!(session.revision(), before + 1);
    assert_eq!(session.list()[0].id, id);
    assert_eq!(session.list()[0].name, "after");
    assert_eq!(session.list()[0].field_names, vec!["token".to_owned()]);
}

#[test]
fn rejected_whole_record_replace_changes_nothing() {
    let mut session = session();
    let id = session.add("first", vec![field("value", b"one")]).unwrap();
    session
        .add("occupied", vec![field("value", b"two")])
        .unwrap();
    let revision = session.revision();
    let touches = session.activity().touches;
    let reference = SecretRef::parse(&format!("id:{id}")).unwrap();

    assert_eq!(
        session
            .prepare_record_replacement(
                &reference,
                "occupied",
                vec![field("value", b"replacement")],
            )
            .unwrap_err(),
        LadonError::DuplicateSecretName
    );
    assert_eq!(session.revision(), revision);
    assert_eq!(session.activity().touches, touches);
    assert_eq!(session.list()[0].name, "first");
}
