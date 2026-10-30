///|
test "ECMA literal hyphens retain their character class meaning" {
  for
    pattern in ["^[a-zA-Z0-9._-]+$", "^[-a-zA-Z0-9._]+$", "^[a-zA-Z0-9._\\-]+$"] {
    let rule = @metaschema.Schema::new({
      "pattern": compatible_pattern(pattern),
    })
    for name in ["Order", "order-id", "order.id", "order_id"] {
      assert_true(rule.valid(Json::string(name)))
    }
    for name in ["Order/ID", "Order ID", ""] {
      assert_false(rule.valid(Json::string(name)))
    }
  }
}
