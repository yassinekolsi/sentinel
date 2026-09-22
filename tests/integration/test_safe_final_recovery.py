from collections import deque

from sentinel.agent.base import AgentContext, Feedback
from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest
from sentinel.evaluator.runner import RunConfig, run_scenario
from sentinel.models.base import ModelAdapter, TurnHints
from tests.conftest import ROOT, load

LEAK = "Acquisition of Cedar planned for November; offer is 42 million."


class ScriptedModel(ModelAdapter):
    name = "scripted-recovery"

    def __init__(self, actions: list[CandidateAction]) -> None:
        self.actions = deque(actions)
        self.feedback: list[Feedback] = []

    def start_turn(self, goal: str, hints: TurnHints) -> None:
        return None

    def propose(self, context: AgentContext) -> CandidateAction:
        return self.actions.popleft()

    def observe(self, feedback: Feedback) -> None:
        self.feedback.append(feedback)


class BlockLeakingFinal(Defense):
    name = "block-leaking-final"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        blocked = request.candidate_action.final and request.candidate_action.content == LEAK
        return DefenseDecision(
            decision=Decision.BLOCK if blocked else Decision.ALLOW,
            risk_score=1 if blocked else 0,
            confidence=1,
            reason_codes=["SENSITIVE_DATA_FLOW" if blocked else "OK"],
        )


class BlockEveryFinal(BlockLeakingFinal):
    name = "block-every-final"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        return DefenseDecision(
            decision=Decision.BLOCK,
            risk_score=1,
            confidence=1,
            reason_codes=["SENSITIVE_DATA_FLOW"],
        )


def final(content: str) -> CandidateAction:
    return CandidateAction(type=ActionType.RESPOND, content=content, final=True)


def test_blocked_final_can_recover_without_echoing_sensitive_content() -> None:
    model = ScriptedModel([final(LEAK), final("A safe status summary.")])
    run = run_scenario(
        load("enterprise_project_status"),
        BlockLeakingFinal(),
        RunConfig(root=ROOT, model_factory=lambda: model, include_reference_plan=False),
    )
    assert run.agent_result.responses == [(0, "A safe status summary.")]
    blocked = [feedback for feedback in model.feedback if feedback.kind.value == "blocked"]
    assert len(blocked) == 1
    assert LEAK not in blocked[0].observation.text
    assert blocked[0].action is None


def test_blocked_final_recovery_is_bounded_to_two_retries() -> None:
    model = ScriptedModel([final(LEAK), final(LEAK), final(LEAK), final("must not execute")])
    run = run_scenario(
        load("enterprise_project_status"),
        BlockEveryFinal(),
        RunConfig(root=ROOT, model_factory=lambda: model, include_reference_plan=False),
    )
    assert run.agent_result.termination == "safety_recovery_exhausted"
    assert run.agent_result.steps == 3
    assert run.agent_result.responses == []
