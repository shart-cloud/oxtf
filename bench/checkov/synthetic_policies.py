"""Synthetic Checkov policies for operators and shapes the built-in catalog
does not exercise. Each is run by `graph_compare.py` against Checkov's own
parser and solvers, exactly like a built-in graph policy.

Every attribute operator appears as a plain attribute, under a wildcard path,
and as `jsonpath_<operator>`; selected ones also inside connection trees and
with `resource_types: all` scopes.
"""

T = "aws_s3_bucket"
OPERANDS = {
    "exists": None,
    "not_exists": None,
    "equals": "private",
    "not_equals": "private",
    "equals_ignore_case": "PRIVATE",
    "not_equals_ignore_case": "PRIVATE",
    "within": ["private", "log-delivery-write", 1, True],
    "not_within": ["private", "log-delivery-write"],
    "contains": "prod",
    "not_contains": "prod",
    "starting_with": "pro",
    "not_starting_with": "pro",
    "ending_with": "-prod",
    "not_ending_with": "-prod",
    "greater_than": 5,
    "greater_than_or_equal": "5",
    "less_than": 5,
    "less_than_or_equal": 5,
    "is_empty": None,
    "is_not_empty": None,
    "is_true": None,
    "is_false": None,
    "regex_match": "^(prod|stage)-[a-z]+$",
    "not_regex_match": "(?i)^ROOT$",
    "intersects": ["a", "prod", 1],
    "not_intersects": "prod",
    "subset": ["a", "b", 1],
    "not_subset": ["a", "b"],
    "any": None,
    "length_equals": 2,
    "length_not_equals": 2,
    "length_greater_than": 1,
    "length_greater_than_or_equal": "2",
    "length_less_than": 3,
    "length_less_than_or_equal": 2,
    "number_of_words_equals": 2,
    "number_of_words_not_equals": 2,
    "number_of_words_greater_than": 1,
    "number_of_words_greater_than_or_equal": 2,
    "number_of_words_less_than": 3,
    "number_of_words_less_than_or_equal": 2,
    "cidr_range_subset": ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"],
    "cidr_range_not_subset": "10.0.0.0/8",
    "range_includes": ["22", "8000-8100", 443],
    "range_not_includes": 22,
}

# Extra operand variants for operators whose semantics depend on the operand.
VARIANTS = {
    "regex_match": [".*db2-ae.*", "[0-9]{2,}", r"\d+\.\d+", "(?i)prod$"],
    "intersects": ["prod", ["x"]],
    "range_includes": ["0-1023", "22-80"],
    "cidr_range_subset": ["0.0.0.0/0", ["::/0"]],
    "length_equals": [0],
}


def policy(name, definition, scope=None):
    doc = {"metadata": {"id": name, "name": name, "category": "GENERAL_SECURITY"}, "definition": definition}
    if scope:
        doc["scope"] = {"provider": scope}
    return doc


def attribute(op, value, attribute="acl", types=(T,)):
    leaf = {"cond_type": "attribute", "resource_types": list(types), "attribute": attribute, "operator": op}
    if value is not None:
        leaf["value"] = value
    return leaf


def policies():
    out = []
    for op, value in OPERANDS.items():
        for i, v in enumerate([value] + VARIANTS.get(op, [])):
            out.append(policy(f"SYN_{op}_{i}", attribute(op, v)))
        out.append(policy(f"SYN_{op}_wildcard", attribute(op, value, "rule.*.name")))
        out.append(policy(f"SYN_jsonpath_{op}", attribute(f"jsonpath_{op}", value, "rule[*].name")))
        out.append(policy(f"SYN_jsonpath_{op}_filter",
                          attribute(f"jsonpath_{op}", value, "rule[?(@.kind == 'ingress')].name")))
    # JSONPath filters beyond string equality.
    for i, attr in enumerate([
        "rule[?(@.kind =~ '(?i)^INGRESS$')].name",
        "rule[?(@.port == 22)].name",
        "rule[?(@.port > 1024 & @.kind != 'egress')].name",
        "rule[?(@.port <= 443)]",
        "rule[?(@.port >= 1)].kind",
    ]):
        out.append(policy(f"SYN_filter_{i}", attribute("jsonpath_exists", None, attr)))
        out.append(policy(f"SYN_filter_{i}_equals", attribute("jsonpath_equals", "ingress", attr)))
    # Boolean trees and connections around the new operators.
    out.append(policy("SYN_tree_0", {"and": [
        attribute("regex_match", "^prod-", "bucket"),
        {"or": [attribute("length_less_than", 3, "tags"), attribute("intersects", ["a"], "tags")]},
        {"not": attribute("cidr_range_subset", "10.0.0.0/8", "cidr")},
    ]}))
    out.append(policy("SYN_tree_1", {"or": [
        {"cond_type": "connection", "resource_types": [T], "connected_resource_types": ["aws_s3_bucket_policy"],
         "operator": "exists"},
        attribute("range_includes", "8000-9000", "port"),
    ]}))
    out.append(policy("SYN_tree_2", {"and": [
        {"cond_type": "connection", "resource_types": [T], "connected_resource_types": ["aws_s3_bucket_policy"],
         "operator": "exists"},
        attribute("number_of_words_greater_than", 1, "description", ["aws_s3_bucket_policy"]),
    ]}))
    # `resource_types: all`, scoped and unscoped, and a missing type list.
    for scope in (None, "aws", "GCP", "oci"):
        out.append(policy(f"SYN_all_{scope}", {"cond_type": "attribute", "resource_types": "all",
                                               "attribute": "acl", "operator": "exists"}, scope))
    out.append(policy("SYN_all_missing", {"cond_type": "attribute", "attribute": "acl", "operator": "not_exists"}))
    out.append(policy("SYN_all_first", {"cond_type": "attribute", "resource_types": ["ALL", T],
                                        "attribute": "acl", "operator": "exists"}, "aws"))
    out.append(policy("SYN_connected_all", {"cond_type": "connection", "resource_types": [T],
                                            "connected_resource_types": ["All"], "operator": "exists"}, "aws"))
    return out
