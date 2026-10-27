///|
/// A positive permission fact. Scope and role facts also establish possession
/// of the named credential; no hierarchy between scope or role names is inferred.
pub(all) enum Atom {
  Credential(String)
  Scope(String, String)
  Role(String, String)
} derive(Eq, Debug)

///|
pub extend Atom with Eq::{equal, not_equal}

///|
pub extend Atom with Debug::{to_repr}

///|
/// A closed set of positive permission facts. Construction and accessors copy
/// arrays so callers cannot change the facts after construction.
pub struct GrantSet {
  priv facts : Array[Atom]
} derive(Eq, Debug)

///|
pub extend GrantSet with Eq::{equal, not_equal}

///|
pub extend GrantSet with Debug::{to_repr}

///|
fn atom_scheme(atom : Atom) -> String {
  match atom {
    Credential(scheme) | Scope(scheme, _) | Role(scheme, _) => scheme
  }
}

///|
fn atom_kind(atom : Atom) -> Int32 {
  match atom {
    Credential(_) => 0
    Scope(_, _) => 1
    Role(_, _) => 2
  }
}

///|
fn atom_value(atom : Atom) -> String {
  match atom {
    Credential(_) => ""
    Scope(_, value) | Role(_, value) => value
  }
}

///|
fn atom_compare(left : Atom, right : Atom) -> Int32 {
  let scheme_order = atom_scheme(left).compare(atom_scheme(right))
  if scheme_order != 0 {
    return scheme_order
  }
  let kind_order = atom_kind(left).compare(atom_kind(right))
  if kind_order != 0 {
    return kind_order
  }
  atom_value(left).compare(atom_value(right))
}

///|
fn close_atoms(atoms : Array[Atom]) -> Array[Atom] {
  let closed = []
  for atom in atoms {
    closed.push(atom)
    match atom {
      Scope(scheme, _) | Role(scheme, _) => closed.push(Credential(scheme))
      Credential(_) => ()
    }
  }
  closed.sort_by(atom_compare)
  let unique = []
  for atom in closed {
    if unique.is_empty() || unique[unique.length() - 1] != atom {
      unique.push(atom)
    }
  }
  unique
}

///|
/// Construct grants, adding credential possession implied by every scope and
/// role. Repeated facts are removed and the resulting order is deterministic.
pub fn GrantSet::new(atoms : Array[Atom]) -> GrantSet {
  { facts: close_atoms(atoms), }
}

///|
/// Return an independent copy of the canonical, closed facts.
pub fn GrantSet::atoms(self : GrantSet) -> Array[Atom] {
  self.facts.copy()
}

///|
// Both operands are sorted and unique. A merge walk avoids searching every
// required fact independently in wide conjunctions.
fn atoms_subset(required : Array[Atom], available : Array[Atom]) -> Bool {
  for need = 0, have = 0; need < required.length(); {
    if have == available.length() {
      return false
    }
    let order = atom_compare(required[need], available[have])
    if order < 0 {
      return false
    } else if order == 0 {
      continue need + 1, have + 1
    } else {
      continue need, have + 1
    }
  }
  true
}
