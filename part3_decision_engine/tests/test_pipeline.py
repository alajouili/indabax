from sentinel_decision.human import ScriptedApprover
from sentinel_decision.models import HumanResponse, Outcome
from sentinel_decision.pipeline import DecisionPipeline


def test_clean_allows_and_executes(policy, sample, trace):
    called = []
    pipeline = DecisionPipeline(policy, trace_log=trace)
    result = pipeline.run(sample("clean"), executor=lambda action: called.append(action.tool) or "ok")
    assert result.outcome is Outcome.ALLOW
    assert result.executed is True
    assert called == ["summarize"]


def test_bad_blocks_and_executor_is_never_called(policy, sample, trace):
    called = []
    pipeline = DecisionPipeline(policy, trace_log=trace)
    result = pipeline.run(sample("bad"), executor=lambda action: called.append(action.tool))
    assert result.outcome is Outcome.BLOCK
    assert result.executed is False
    assert called == []


def test_mixed_escalate_approve_and_deny(policy, sample, tmp_path):
    proposal = sample("mixed")

    called_approve = []
    approve = DecisionPipeline(
        policy,
        approver=ScriptedApprover([HumanResponse.APPROVED]),
        trace_log=__import__("sentinel_decision.tracelog", fromlist=["TraceLog"]).TraceLog(tmp_path / "approve.jsonl"),
    )
    result_a = approve.run(proposal, executor=lambda action: called_approve.append(action.tool) or "ok")
    assert result_a.outcome is Outcome.ESCALATE
    assert result_a.human_response is HumanResponse.APPROVED
    assert result_a.executed is True
    assert called_approve == ["send_email"]

    called_deny = []
    deny = DecisionPipeline(
        policy,
        approver=ScriptedApprover([HumanResponse.DENIED]),
        trace_log=__import__("sentinel_decision.tracelog", fromlist=["TraceLog"]).TraceLog(tmp_path / "deny.jsonl"),
    )
    result_d = deny.run(proposal, executor=lambda action: called_deny.append(action.tool))
    assert result_d.outcome is Outcome.ESCALATE
    assert result_d.human_response is HumanResponse.DENIED
    assert result_d.executed is False
    assert called_deny == []


def test_engine_is_deterministic_through_pipeline(policy, sample, tmp_path):
    from sentinel_decision.tracelog import TraceLog

    proposal = sample("clean")
    p1 = DecisionPipeline(policy, trace_log=TraceLog(tmp_path / "one.jsonl"))
    p2 = DecisionPipeline(policy, trace_log=TraceLog(tmp_path / "two.jsonl"))
    a = p1.run(proposal)
    b = p2.run(proposal)
    # Trace timestamps/hashes differ; the decision output itself must not.
    assert a == b


def test_pipeline_can_call_part2_provider(policy, trace):
    from sentinel_decision.part2_client import InProcessPart2Provider

    def fake_analyze(payload):
        return {
            "action_id": payload["action_id"],
            "ml_label": "benign",
            "ml_confidence": 0.01,
            "semantic_similarity": 0.95,
            "content_flags": [],
        }

    proposal = {
        "action_id": "a-part2",
        "trust_level": "TRUSTED_INTERNAL",
        "permission_ok": True,
        "structural_flags": [],
        "user_task": "summarize thread",
        "proposed_action_description": "summarize the email thread",
        "instruction_content": "ordinary email",
        "action": {"tool": "summarize", "params": {}},
    }
    pipeline = DecisionPipeline(
        policy,
        trace_log=trace,
        part2_provider=InProcessPart2Provider(fake_analyze),
    )
    result = pipeline.run(proposal)
    assert result.action_id == "a-part2"
    assert "INPUT_INCOMPLETE" not in result.reason_codes
