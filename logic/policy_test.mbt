///|
test "anonymous and denied policies retain their Boolean meaning" {
  let anonymous = @logic.Policy::anonymous()
  let denied = @logic.Policy::denied()
  let empty = @logic.GrantSet::new([])
  let credential = @logic.Policy::new([[@logic.Credential("token")]])
  assert_true(anonymous.allows(empty))
  assert_false(denied.allows(empty))
  assert_true(denied.implies(credential))
  assert_true(credential.implies(anonymous))
  assert_false(anonymous.implies(credential))
  assert_eq(anonymous, @logic.Policy::new([[]]))
  assert_eq(denied, @logic.Policy::new([]))
  assert_eq(denied.witness_against(anonymous), None)
  assert_eq(anonymous.witness_against(denied), Some(empty))
}

///|
test "AND requirements and OR alternatives produce exact weakening witnesses" {
  let first = @logic.Credential("first")
  let second = @logic.Credential("second")
  let both = @logic.Policy::new([[first, second]])
  let either = @logic.Policy::new([[first], [second]])
  assert_true(both.implies(either))
  assert_false(either.implies(both))
  let witness = either.witness_against(both).unwrap()
  assert_eq(witness.atoms(), [first])
  assert_true(either.allows(witness))
  assert_false(both.allows(witness))
}

///|
test "scope and role facts imply only their own credential" {
  let credential = @logic.Policy::new([[@logic.Credential("token")]])
  let read = @logic.Policy::new([[@logic.Scope("token", "read")]])
  let admin = @logic.Policy::new([[@logic.Role("token", "admin")]])
  let grants = @logic.GrantSet::new([@logic.Scope("token", "read")])
  assert_true(credential.allows(grants))
  assert_true(read.allows(grants))
  assert_false(admin.allows(grants))
  assert_false(
    @logic.Policy::new([[@logic.Credential("other")]]).allows(grants),
  )
  assert_true(read.implies(credential))
  assert_true(admin.implies(credential))
  assert_false(read.implies(admin))
  assert_false(admin.implies(read))
  assert_false(credential.implies(read))
}

///|
test "literal scope reduction and mixed changes both expose new grants" {
  let read = @logic.Scope("token", "read")
  let write = @logic.Scope("token", "write")
  let old = @logic.Policy::new([[read, write]])
  let next = @logic.Policy::new([[read]])
  let witness = next.witness_against(old).unwrap()
  assert_true(next.allows(witness))
  assert_false(old.allows(witness))
  assert_true(old.implies(next))
  let unrelated = @logic.Policy::new([[@logic.Credential("different")]])
  assert_false(next.implies(unrelated))
  assert_false(unrelated.implies(next))
  let forward = next.witness_against(unrelated).unwrap()
  let backward = unrelated.witness_against(next).unwrap()
  assert_true(next.allows(forward))
  assert_false(unrelated.allows(forward))
  assert_true(unrelated.allows(backward))
  assert_false(next.allows(backward))
}

///|
test "canonicalization removes duplicates and dominated alternatives" {
  let token = @logic.Credential("token")
  let read = @logic.Scope("token", "read")
  let write = @logic.Scope("token", "write")
  let noisy = @logic.Policy::new([
    [write, token, read, read],
    [read],
    [token, read],
    [@logic.Credential("other"), read],
  ])
  assert_eq(noisy.alternatives(), [[token, read]])
  assert_eq(noisy, @logic.Policy::new([[read]]))
  assert_eq(
    @logic.Policy::new([[read], [], [write]]),
    @logic.Policy::anonymous(),
  )
  assert_eq(@logic.GrantSet::new([write, read, read]).atoms(), [
    token, read, write,
  ])
}

///|
test "public array boundaries do not expose policy and grant storage" {
  let token = @logic.Credential("token")
  let clause = [token]
  let alternatives = [clause]
  let policy = @logic.Policy::new(alternatives)
  clause.push(@logic.Credential("later"))
  alternatives.push([])
  let exported = policy.alternatives()
  exported[0].clear()
  exported.push([])
  assert_eq(policy.alternatives(), [[token]])
  let input = [@logic.Scope("token", "read")]
  let grants = @logic.GrantSet::new(input)
  input.clear()
  let facts = grants.atoms()
  facts.clear()
  assert_eq(grants.atoms(), [token, @logic.Scope("token", "read")])
}
