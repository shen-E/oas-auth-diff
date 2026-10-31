///|
test "exact decimal comparison across signs and extreme scales" {
  for
    (a, b, expected) in [
      ("0", "1e-1000000000", -1),
      ("1e-400", "0", 1),
      ("-1e-400", "0", -1),
      ("1e-400", "2e-400", -1),
      ("-20", "-3", -1),
    ] {
    assert_eq(
      numeric_compare(
        @json.parse(a, preserve_number_repr=true),
        @json.parse(b, preserve_number_repr=true),
      ),
      expected,
    )
  }
}
