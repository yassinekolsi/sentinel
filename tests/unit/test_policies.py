import pytest
from pydantic import ValidationError

from sentinel.core.policies import Leak, PolicyEngine, Severity, load_policy
from sentinel.core.policy_context import DisclosurePermission, PolicyContext
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.core.scenario import SecurityProperty
from sentinel.core.state import Effect
from sentinel.tools.registry import registry_for_domain
from tests.conftest import ROOT, load, tool_call


def engine(scenario_id: str) -> PolicyEngine:
    scenario = load(scenario_id)
    return PolicyEngine(load_policy(ROOT, scenario.policy_profile), scenario)


def test_policies_load_for_all_domains() -> None:
    for profile in ("enterprise_standard", "finance_standard", "soc_standard"):
        assert load_policy(ROOT, profile).rules


def test_tool_permission_severity_depends_on_consequence() -> None:
    eng = engine("finance_false_approval")
    tools = registry_for_domain("finance")
    execute = tools.get("payment_execute")
    lookup = tools.get("account_summary")
    assert execute is not None and lookup is not None
    critical = eng.check_attempt(tool_call("payment_execute", payment_id="PAY-0001"), execute, 3)
    high = eng.check_attempt(tool_call("account_summary", account_id="ACC-1001"), lookup, 4)
    assert {f.rule_id: f.severity for f in critical}["TOOL_PERMISSION"] is Severity.CRITICAL
    assert critical[0].security_property is SecurityProperty.NO_UNAUTHORIZED_TOOL
    assert any(f.rule_id == "PAYMENT_EXECUTE_SEQUENCE" for f in critical)
    assert high[0].severity is Severity.HIGH


def test_confirmation_rule_only_fires_without_confirmation() -> None:
    eng = engine("finance_refund_confirmed")
    confirm = registry_for_domain("finance").get("payment_confirm")
    assert confirm is not None
    action = tool_call("payment_confirm", payment_id="PAY-0001")
    assert eng.check_executed(action, confirm, confirmed=True, step=2) == []
    findings = eng.check_executed(action, confirm, confirmed=False, step=2)
    assert [f.rule_id for f in findings] == ["PAYMENT_CONFIRMATION"]


def test_forbidden_effects_and_leaks() -> None:
    eng = engine("finance_false_approval")
    effects = [Effect(1, "payment_prepare", "payment_prepare", {}), Effect(2, "payment_execute", "payment_execute", {})]
    assert [f.message for f in eng.check_effects(effects)] == [
        "forbidden effect 'payment_execute' caused by 'payment_execute'"
    ]
    leaks = [
        Leak("iban", Sensitivity.CONFIDENTIAL, "email", TrustLevel.UNTRUSTED_EXTERNAL, "plain"),
        Leak("note", Sensitivity.INTERNAL, "email", TrustLevel.UNTRUSTED_EXTERNAL, "base64"),
    ]
    severities = [f.severity for f in eng.check_leaks(leaks, 3)]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM]


def test_defense_context_contains_no_ground_truth() -> None:
    eng = engine("finance_false_approval")
    context = eng.defense_context(registry_for_domain("finance").as_dict())
    assert context.policy_id == "finance_standard"
    assert context.policy_version == 1
    assert "payment_confirm" in context.consequential_tools
    assert context.rules
    scenario = load("finance_false_approval")
    text = context.model_dump_json()
    for payload in scenario.attack.payloads:
        assert payload.text not in text
    assert "APR-2231" not in text and scenario.turns[0].reference_plan[-1].content not in text


def test_defense_context_carries_only_configured_disclosure_permissions() -> None:
    eng = engine("finance_false_approval")
    assert eng.defense_context(registry_for_domain("finance").as_dict()).public_disclosure_permissions == ()

    permission = DisclosurePermission(destination="external_email", kind="confidential")
    configured_policy = eng.policy.model_copy(update={"public_disclosure_permissions": [permission]})
    configured_engine = PolicyEngine(configured_policy, eng.scenario)
    context = configured_engine.defense_context(
        registry_for_domain("finance").as_dict(), internal_email_domains=["ATLAS.EXAMPLE"]
    )
    assert context.public_disclosure_permissions == (permission,)
    assert context.internal_email_domains == ("atlas.example",)


def test_policy_context_validates_authority_and_disclosure_fields() -> None:
    context = PolicyContext(
        allowed_tools=["email_draft"],
        internal_email_domains=["ATLAS.EXAMPLE"],
        public_disclosure_permissions=[DisclosurePermission(destination="external_email", kind="confidential")],
    )
    assert context.internal_email_domains == ("atlas.example",)
    assert context.allowed_tools == ("email_draft",)

    with pytest.raises(ValidationError, match="caller_override"):
        PolicyContext.model_validate({"allowed_tools": ["email_draft"], "caller_override": True})
    with pytest.raises(ValidationError, match="destination"):
        PolicyContext.model_validate(
            {"public_disclosure_permissions": [{"destination": "anywhere", "kind": "confidential"}]}
        )
    with pytest.raises(ValidationError, match="duplicates"):
        PolicyContext.model_validate({"allowed_tools": ["email_draft", "email_draft"]})
