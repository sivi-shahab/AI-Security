package system.log_test

import rego.v1

import data.system.log

test_forbidden_fields_masked_anywhere if {
	event := {"input": {
		"channel": "ai_gateway",
		"Prompt": "NIK 3171234567890001",
		"content": {"sensitivity": "internal", "classes": [], "text": "x"},
		"messages": [{"content": "y"}],
	}}
	m := log.mask with input as event with data.system.log.forbidden as ["prompt", "text", "messages", "content"]
	m == {"/input/Prompt", "/input/content", "/input/content/text", "/input/messages", "/input/messages/0/content"}
}

test_clean_input_not_masked if {
	m := log.mask with input as {"input": {"channel": "ai_gateway"}} with data.system.log.forbidden as ["prompt"]
	count(m) == 0
}
