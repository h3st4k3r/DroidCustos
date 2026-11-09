import json

from droidcustos.custody import append_event, verify_custody_log


def test_custody_events_are_hash_chained(tmp_path) -> None:
    """Verify consecutive custody events preserve their hash links."""
    log = tmp_path / "custody.jsonl"
    append_event(log, "case_created", actor="tester")
    append_event(log, "preflight_finished", actor="tester", details={"ready": True})
    result = verify_custody_log(log)
    assert result["verified"] is True
    assert result["chain_complete"] is True
    assert result["events"] == 2

    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert records[1]["previous_event_hash"] == records[0]["event_hash"]


def test_custody_tampering_breaks_the_chain(tmp_path) -> None:
    """Detect changes to an event body after it has been recorded."""
    log = tmp_path / "custody.jsonl"
    append_event(log, "case_created", actor="tester")
    payload = json.loads(log.read_text(encoding="utf-8"))
    payload["actor"] = "modified"
    log.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    result = verify_custody_log(log)
    assert result["verified"] is False
    assert "line-1:event-hash-mismatch" in result["errors"]
