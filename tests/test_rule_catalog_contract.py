"""Contract checks tying the static catalog to executable rule configuration."""

from __future__ import annotations

from dataclasses import fields

from erp_security_evidence_workbench.rules import RULE_REGISTRY, RuleParameters


def test_catalog_parameters_exactly_match_runtime_configuration_defaults() -> None:
    runtime_defaults = RuleParameters()
    runtime_names = {field.name for field in fields(RuleParameters)}
    catalog_parameters = [
        parameter for definition in RULE_REGISTRY for parameter in definition.parameters
    ]

    assert {parameter.name for parameter in catalog_parameters} == runtime_names
    for parameter in catalog_parameters:
        assert parameter.default == getattr(runtime_defaults, parameter.name)


def test_every_non_configurable_literal_predicate_is_an_explicit_fixed_condition() -> None:
    fixed_conditions = {
        definition.rule_id: {
            condition.name: condition.default for condition in definition.fixed_conditions
        }
        for definition in RULE_REGISTRY
    }

    assert fixed_conditions == {
        "ERP001": {"control": "AUDIT_LOGGING", "enabled": False},
        "ERP002": {"enabled": True},
        "ERP003": {"assignment_mode": "direct"},
        "ERP004": {},
        "ERP005": {
            "action": "SIGN_IN",
            "outcome": "success",
            "principal_kind": "emergency",
        },
        "ERP006": {"action": "SIGN_IN", "outcome": "failure"},
    }
