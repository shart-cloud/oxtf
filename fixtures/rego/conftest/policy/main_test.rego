package main

import rego.v1

test_unpinned_module_is_denied if {
	cfg := parse_config("hcl2", `module "m" { source = "git::https://example.com/m.git" }`)
	deny_unpinned_module["module m is not pinned to a ref"] with input as cfg
}

test_pinned_module_passes if {
	cfg := parse_config_file("pinned.tf")
	count(deny_unpinned_module) == 0 with input as cfg
}

test_a_failing_test_fails if {
	cfg := parse_config("hcl2", `module "m" { source = "./local" }`)
	deny_unpinned_module["module m is not pinned to a ref"] with input as cfg
}

todo_test_regions if false
