///|
/// A disjunction of conjunctions of positive authorization facts.
/// An empty conjunction permits anonymous access; no alternatives denies all.
/// Alternatives are closed over credential possession and canonically reduced.
pub struct Policy {
  priv clauses : Array[Array[Atom]]
} derive(Eq, Debug)

///|
pub extend Policy with Eq::{equal, not_equal}

///|
pub extend Policy with Debug::{to_repr}

///|
fn clause_compare(left : Array[Atom], right : Array[Atom]) -> Int32 {
  let length_order = left.length().compare(right.length())
  if length_order != 0 {
    return length_order
  }
  for index in 0..<left.length() {
    let order = atom_compare(left[index], right[index])
    if order != 0 {
      return order
    }
  }
  0
}

///|
/// Build a policy from OR alternatives whose facts must each all hold.
/// Redundant alternatives and facts are removed without changing acceptance.
///
/// ```mbt check
/// test {
///   let old = @logic.Policy::new([
///     [@logic.Scope("token", "read"), @logic.Scope("token", "write")],
///   ])
///   let next = @logic.Policy::new([[@logic.Scope("token", "read")]])
///   let witness = next.witness_against(old).unwrap()
///   assert_true(next.allows(witness))
///   assert_false(old.allows(witness))
/// }
/// ```
pub fn Policy::new(alternatives : Array[Array[Atom]]) -> Policy {
  let closed = alternatives.map(close_atoms)
  closed.sort_by(clause_compare)
  let clauses = []
  for clause in closed {
    if !clauses.any(existing => atoms_subset(existing, clause)) {
      clauses.push(clause)
    }
  }
  { clauses, }
}

///|
/// A policy that accepts the empty set of credentials and every stronger set.
pub fn Policy::anonymous() -> Policy {
  { clauses: [[]], }
}

///|
/// A policy that accepts no grant set.
pub fn Policy::denied() -> Policy {
  { clauses: [], }
}

///|
/// Return deep copies of the canonical OR alternatives.
pub fn Policy::alternatives(self : Policy) -> Array[Array[Atom]] {
  self.clauses.map(clause => clause.copy())
}

///|
/// Whether at least one full alternative is present in the supplied grants.
pub fn Policy::allows(self : Policy, grants : GrantSet) -> Bool {
  self.clauses.any(clause => atoms_subset(clause, grants.facts))
}

///|
/// Whether every grant set allowed by this policy is also allowed by `other`.
/// Each clause is itself its smallest closed satisfying assignment, so testing
/// those assignments is complete for positive authorization conditions.
pub fn Policy::implies(self : Policy, other : Policy) -> Bool {
  self.clauses.all(clause => {
    other.clauses.any(required => atoms_subset(required, clause))
  })
}

///|
/// Find a deterministic, closed grant set allowed by this policy but rejected
/// by `other`. `None` means this policy implies the other policy.
pub fn Policy::witness_against(self : Policy, other : Policy) -> GrantSet? {
  for clause in self.clauses {
    if !other.clauses.any(required => atoms_subset(required, clause)) {
      return Some({ facts: clause.copy(), })
    }
  }
  None
}
