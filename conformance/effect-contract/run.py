#!/usr/bin/env python3
"""Deterministic simulator for ambiguous tool side effects.

This exercises the harness policy against synthetic services only. It does not
probe, certify, or make claims about a live MCP server.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCENARIOS = ROOT / "scenarios.json"


class FakeService:
    """Synthetic service with optional server-enforced idempotency."""

    def __init__(self, idempotency_key_supported: bool) -> None:
        self.idempotency_key_supported = idempotency_key_supported
        self.effects = 0
        self.seen_keys: set[str] = set()

    def write(self, operation_key: str) -> None:
        if self.idempotency_key_supported:
            if operation_key in self.seen_keys:
                return
            self.seen_keys.add(operation_key)
        self.effects += 1


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    contract = case["contract"]
    service = FakeService(contract["idempotency_key_supported"])
    op_key = case["id"]
    fault = case["fault"]
    action: str

    if fault == "ack_lost_after_commit":
        service.write(op_key)
        # The caller cannot infer a failed write from a missing acknowledgement.
        if contract["idempotency_key_supported"] and contract["key_reused_across_attempts"]:
            action = "RETRY_WITH_SAME_KEY"
            service.write(op_key)
        else:
            action = "HOLD_FOR_RECONCILIATION"
    elif fault == "duplicate_delivery":
        service.write(op_key)
        if contract["idempotency_key_supported"] and contract["key_reused_across_attempts"]:
            action = "ALLOW_DEDUPLICATED_REPLAY"
            service.write(op_key)
        else:
            # A local durable operation ledger blocks a duplicate while uncertain.
            action = "BLOCK_DUPLICATE"
    elif fault == "timeout_outcome_unknown":
        # The fixture intentionally does not disclose whether a commit occurred.
        action = "HOLD_FOR_RECONCILIATION"
    else:
        raise ValueError(f"unsupported fault: {fault}")

    return {
        "id": case["id"],
        "action": action,
        "expected_action": case["expected_action"],
        "effect_count": service.effects,
        "expected_effect_count": case["expected_effect_count"],
        "mcp_idempotent_hint": contract["mcp_idempotent_hint"],
        "passed": (
            action == case["expected_action"]
            and service.effects == case["expected_effect_count"]
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON results")
    args = parser.parse_args()

    cases = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    results = [run_case(case) for case in cases]
    passed = sum(result["passed"] for result in results)
    report = {
        "harness": "vortex-effect-contract",
        "version": "0.1.0",
        "scope": "synthetic simulator; not live-server certification",
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Vortex Effect Contract Harness v0.1.0")
        print("Scope: synthetic scenarios only; no live MCP server was tested.")
        for result in results:
            status = "PASS" if result["passed"] else "FAIL"
            print(
                f"{status} {result['id']}: action={result['action']}, "
                f"effects={result['effect_count']}"
            )
        print(f"Result: {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
