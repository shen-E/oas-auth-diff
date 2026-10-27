///|
// Evaluate raw formulas directly over raw assignments. This oracle deliberately
// does not call policy normalization, implication, or its subset algorithm.
fn fact_holds(atom : @logic.Atom, assignment : Array[@logic.Atom]) -> Bool {
  match atom {
    Credential(scheme) =>
      assignment.any(fact => {
        match fact {
          Credential(name) | Scope(name, _) | Role(name, _) => name == scheme
        }
      })
    Scope(_, _) | Role(_, _) => assignment.contains(atom)
  }
}

///|
fn formula_holds(
  formula : Array[Array[@logic.Atom]],
  assignment : Array[@logic.Atom],
) -> Bool {
  formula.any(clause => clause.all(atom => fact_holds(atom, assignment)))
}

///|
fn powerset(universe : Array[@logic.Atom]) -> Array[Array[@logic.Atom]] {
  Array::makei(1 << universe.length(), mask => {
    let chosen = []
    for index in 0..<universe.length() {
      if (mask & (1 << index)) != 0 {
        chosen.push(universe[index])
      }
    }
    chosen
  })
}

///|
fn verify_models(
  formulas : Array[Array[Array[@logic.Atom]]],
  assignments : Array[Array[@logic.Atom]],
) -> Unit raise {
  let policies = formulas.map(@logic.Policy::new)
  let truth_tables = []
  for formula_index, formula in formulas {
    let mut bits = 0
    for assignment_index, assignment in assignments {
      let expected = formula_holds(formula, assignment)
      assert_eq(
        policies[formula_index].allows(@logic.GrantSet::new(assignment)),
        expected,
      )
      if expected {
        bits = bits | (1 << assignment_index)
      }
    }
    truth_tables.push(bits)
  }
  for left_index, left in policies {
    for right_index, right in policies {
      let left_truth = truth_tables[left_index]
      let right_truth = truth_tables[right_index]
      let expected = (left_truth & right_truth) == left_truth
      assert_eq(left.implies(right), expected)
      match left.witness_against(right) {
        None => assert_true(expected)
        Some(witness) => {
          assert_false(expected)
          // Verify against the untouched raw formulas as well as both APIs.
          assert_true(formula_holds(formulas[left_index], witness.atoms()))
          assert_false(formula_holds(formulas[right_index], witness.atoms()))
          assert_true(left.allows(witness))
          assert_false(right.allows(witness))
        }
      }
    }
  }
}

///|
test "all three-credential monotone formulas match exhaustive truth tables" {
  let clauses = powerset([
    @logic.Credential("a"),
    @logic.Credential("b"),
    @logic.Credential("c"),
  ])
  // Every subset of all eight conjunctions: 256 formulas, 65,536 pairs.
  let formulas = Array::makei(1 << clauses.length(), mask => {
    let alternatives = []
    for index in 0..<clauses.length() {
      if (mask & (1 << index)) != 0 {
        alternatives.push(clauses[index])
      }
    }
    alternatives
  })
  verify_models(formulas, clauses)
}

///|
test "credential implications with scopes and roles match independent models" {
  let assignments = powerset([
    @logic.Credential("a"),
    @logic.Scope("a", "read"),
    @logic.Role("a", "admin"),
    @logic.Credential("b"),
  ])
  let formulas : Array[Array[Array[@logic.Atom]]] = [[]]
  for first_index, first in assignments {
    formulas.push([first])
    for second_index in (first_index + 1)..<assignments.length() {
      formulas.push([first, assignments[second_index]])
    }
  }
  // 137 raw formulas include implied credentials, OR branches and redundancy.
  verify_models(formulas, assignments)
}
