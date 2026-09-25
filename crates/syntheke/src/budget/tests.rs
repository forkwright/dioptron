use super::*;

#[test]
fn get_reads_the_field_for_each_dimension() {
    let ceilings = Ceilings {
        wall_time_ms: Some(1),
        fetches: Some(2),
        bytes_transferred: Some(3),
        output_bytes: Some(4),
        tokens: Some(5),
        ops_band: Some(6),
    };
    let cost = Cost {
        wall_time_ms: 11,
        fetches: 12,
        bytes_transferred: 13,
        output_bytes: 14,
        tokens: 15,
        ops_band: 16,
    };
    let expected = [
        ("wall_time_ms", 1, 11),
        ("fetches", 2, 12),
        ("bytes_transferred", 3, 13),
        ("output_bytes", 4, 14),
        ("tokens", 5, 15),
        ("ops_band", 6, 16),
    ];
    assert_eq!(
        Dimension::ALL.len(),
        expected.len(),
        "every dimension has an expectation"
    );
    for (&dimension, (name, ceiling, amount)) in Dimension::ALL.iter().zip(expected) {
        assert_eq!(dimension.name(), name, "dimension names are snake case");
        assert_eq!(ceilings.get(dimension), Some(ceiling), "{name} ceiling");
        assert_eq!(cost.get(dimension), amount, "{name} amount");
    }
}

#[test]
fn default_ceilings_set_no_dimension() {
    let ceilings = Ceilings::default();
    assert!(
        Dimension::ALL.iter().all(|&d| ceilings.get(d).is_none()),
        "a default grant sets no ceiling of its own"
    );
}
