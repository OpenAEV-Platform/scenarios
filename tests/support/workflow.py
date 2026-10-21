"""Closed lists of keys of an export, for the tests: those of the repository's data file."""

from typing import Any

from scenario_tools.domain.shared.workflow import ExportKeys

KEYS_DOCUMENT: dict[str, Any] = {
    "export_versions": [1],
    "workflow": {
        "keys": [
            "workflow_version",
            "workflow_steps",
            "workflow_rate_limit_enabled",
            "workflow_max_attempts",
            "workflow_max_temporal_rate_seconds",
            "workflow_timeout_enabled",
            "workflow_timeout_seconds",
            "workflow_safe_mode_enabled",
            "workflow_scope_rules",
            "workflow_scope_variables",
            "workflow_standalone_conditions",
            "workflow_scope_rule_team_members",
        ]
    },
    "step": {
        "keys": [
            "step_id",
            "step_action_class",
            "step_output",
            "step_output_parser",
            "step_input",
            "step_data",
            "step_limit_execution",
            "step_condition_executed",
            "step_conditions",
        ]
    },
    "condition": {
        "keys": [
            "condition_id",
            "condition_key",
            "condition_key_types",
            "condition_type",
            "condition_mapping_type",
            "condition_value",
            "condition_name",
            "condition_description",
            "condition_parent_id",
            "condition_step_from_id",
            "condition_is_root",
        ],
        "legacy": ["condition_key_type"],
    },
    "scope_rule": {"keys": ["workflow_scope_rule_value", "workflow_scope_rule_source"]},
    "scope_variable": {"keys": ["scope_variable_key", "scope_variable_value"]},
}
KEYS = ExportKeys.from_document(KEYS_DOCUMENT)
