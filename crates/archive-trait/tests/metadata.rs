use archive_trait::{PaxVendorRecords, PaxVendorValue};

#[test]
fn vendor_snapshots_expose_borrowed_values_and_explicit_deletions() {
    let records: PaxVendorRecords = [
        ("Acme.attribute", PaxVendorValue::Value(b"first".to_vec())),
        ("Acme.deleted", PaxVendorValue::Value(b"old".to_vec())),
        ("Acme.attribute", PaxVendorValue::Value(b"last".to_vec())),
        ("Acme.deleted", PaxVendorValue::Deleted),
        ("Acme.binary", PaxVendorValue::Value(vec![0xff, 0, b'\n'])),
    ]
    .into_iter()
    .collect();

    assert_eq!(records.len(), 3);
    assert!(!records.is_empty());
    assert_eq!(
        records.get("Acme.attribute"),
        Some(PaxVendorValue::Value(b"last".as_slice()))
    );
    assert_eq!(records.get("Acme.deleted"), Some(PaxVendorValue::Deleted));
    assert_eq!(records.get("Acme.missing"), None);
    assert_eq!(records.get("Acme.Attribute"), None);

    let mut actual = records.iter().collect::<Vec<_>>();
    actual.sort_by_key(|(keyword, _)| *keyword);
    assert_eq!(
        actual,
        [
            ("Acme.attribute", PaxVendorValue::Value(b"last".as_slice())),
            (
                "Acme.binary",
                PaxVendorValue::Value([0xff, 0, b'\n'].as_slice()),
            ),
            ("Acme.deleted", PaxVendorValue::Deleted),
        ]
    );
}
