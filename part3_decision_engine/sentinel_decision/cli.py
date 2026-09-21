from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_policy
from .human import CLIApprover, DenyAllApprover
from .pipeline import DecisionPipeline
from .tracelog import TraceLog


def _json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-decision")
    ap.add_argument("--policy", default=None)
    sub = ap.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="evaluate one proposal JSON")
    run.add_argument("proposal")
    run.add_argument("--human", choices=("cli", "deny"), default="deny")

    show = sub.add_parser("show", help="show trace-log records")
    show.add_argument("--log", default=None)

    verify = sub.add_parser("verify", help="verify trace-log hash chain")
    verify.add_argument("--log", default=None)

    args = ap.parse_args()
    policy = load_policy(args.policy)
    log_path = args.log if hasattr(args, "log") and args.log else policy.logging.path
    trace = TraceLog(
        log_path,
        redact_param_keys=policy.logging.redact_param_keys,
        safe_placeholder=policy.logging.safe_placeholder,
    )
    if args.command == "run":
        approver = CLIApprover() if args.human == "cli" else DenyAllApprover()
        pipeline = DecisionPipeline(policy, approver=approver, trace_log=trace)
        verdict = pipeline.run(_json(args.proposal))
        print(json.dumps(verdict.model_dump(mode="json"), indent=2, ensure_ascii=False))
    elif args.command == "show":
        print(json.dumps(trace.read(), indent=2, ensure_ascii=False))
    elif args.command == "verify":
        ok, message = trace.verify()
        print(message)
        raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
