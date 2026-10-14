package experiment
import rego.v1

# Integers encode the existing native ordering: False < Unknown < Tainted < True.
rank := {"false": 0, "unknown": 1, "tainted": 2, "true": 3}

matches(v, p) := v != true if p == "not_true"
else := v == true if p == "equals_true"

boolean_rank(v, p) := 3 if matches(v, p)
else := 0

value_rank(v, p) := boolean_rank(v.value, p) if v.kind == "known"
else := 1 if v.kind == "unknown"
else := 2 if v.kind == "tainted"
else := alternatives_rank(v, p) if v.kind == "one_of"

# Experiment scope: flattened, finite Known boolean/null alternatives.
alternatives_rank(v, p) := 3 if {
    count(v.alternatives) > 0
    every a in v.alternatives { matches(a, p) }
} else := 0 if {
    every a in v.alternatives { not matches(a, p) }
} else := 2 if v.tainted
else := 1

combine(a, b) := a if input.op == "single"
else := min([a, b]) if input.op == "and"
else := max([a, b]) if input.op == "or"

# Strategy 1: flatten abstract scalars into null, then execute ordinary booleans.
plain_truth := combine(boolean_rank(input.plain.lhs, input.predicate), boolean_rank(input.plain.rhs, input.predicate))
# Strategy 2: postprocess that same result using all declared evidence states.
# This still cannot recover a result the boolean policy did not emit.
evidence_truth := 0 if plain_truth == 0
else := 1 if "unknown" in [input.lhs.kind, input.rhs.kind]
else := 2 if "tainted" in [input.lhs.kind, input.rhs.kind]
else := plain_truth
# Strategy 3: compose tagged facts according to the native lattice.
tagged_truth := combine(value_rank(input.lhs, input.predicate), value_rank(input.rhs, input.predicate))

# The display location is deliberately independent of deciding evidence.
path_truth := 0 if plain_truth == 0
else := 2 if input.display_tainted
else := plain_truth

result := {"path": path_truth, "evidence": evidence_truth, "tagged": tagged_truth}

# A separate query demonstrates why two uniform substitutions cannot cover
# policies depending on combinations of independently unconstrained inputs.
different := input.a != input.b

# Scalar-evidence probe. The opaque handle is returned unchanged and resolved
# in Rust; a policy cannot manufacture a source location or provenance chain.
probe := {"truth_rank": value_rank(input.value, "not_true"), "evidence": input.value.handle}
