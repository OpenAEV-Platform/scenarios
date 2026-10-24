{
  "base": "cb490ae99a16b3ea43d9d804d62e0ab11988a596",
  "blocking": 0,
  "body": "Closes #4\n\nThe export gives the stored scenario.json again: nothing to propose.\n\nLeft to complete or review:\n- [ ] `scenarios/techniques/linux-discovery-local-account/scenario.json` `/scenario_workflow/workflow_steps/0/step_data/inject_injector_contract/injector_contract_payload`: `already there: process-discovery-ps 1.0.0`\n- [ ] `scenarios/techniques/linux-discovery-local-account/scenario.json` `/scenario_workflow/workflow_steps/1/step_data/inject_injector_contract/injector_contract_payload`: `already there: create-local-account 1.0.0`\n- [ ] `scenarios/techniques/linux-discovery-local-account/scenario.json` `/scenario_workflow/workflow_steps/0/step_data/inject_injector_contract/injector_contract_payload/payload_external_id`: `a payload this scenario did not run before: review what it runs`\n- [ ] `scenarios/techniques/linux-discovery-local-account/scenario.json` `/scenario_workflow/workflow_steps/1/step_data/inject_injector_contract/injector_contract_payload/payload_external_id`: `a payload this scenario did not run before: review what it runs`\n- [ ] `scenarios/techniques/linux-discovery-local-account/scenario.json` `/scenario_workflow/workflow_steps/1/step_data/inject_injector_contract/injector_contract_payload/payload_elevation_required`: `this payload asks for elevated privileges: check why it needs them`\n",
  "changed": false,
  "entry": "scenarios/techniques/linux-discovery-local-account",
  "files": [],
  "mode": "update",
  "title": "feat(scenarios): update linux-discovery-local-account (#4)"
}
