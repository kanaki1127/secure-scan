import pytest

from config.loader import Config, load_config
from output.sarif_merger import compute_fingerprint, merge_sarif
from output.baseline import diff_baseline
from output.console_formatter import format_console
from compliance.mapping import lookup


def _make_result(rule_id="test.rule", uri="a.py", line=1):
    return {
        "ruleId": rule_id,
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            }
        }],
    }


def test_load_config_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "nonexistent.yml"))
    assert isinstance(cfg, Config)
    assert cfg.fail_on_severity == "high"


def test_load_config_invalid_severity(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("fail_on_severity: bogus\n")
    with pytest.raises(ValueError):
        load_config(str(bad))


def test_compute_fingerprint_stable():
    r = _make_result()
    assert compute_fingerprint(r) == compute_fingerprint(r)


def test_merge_sarif_dedupes():
    r = _make_result()
    doc1 = {"runs": [{"results": [r]}]}
    doc2 = {"runs": [{"results": [r]}]}
    merged = merge_sarif([doc1, doc2])
    assert len(merged["runs"][0]["results"]) == 1


def test_diff_baseline():
    r = _make_result()
    baseline = {"runs": [{"results": [r]}]}
    current = {"runs": [{"results": [r]}]}
    diff = diff_baseline(current, baseline)
    assert len(diff["runs"][0]["results"]) == 0


def test_compliance_lookup_case_insensitive():
    assert lookup("cwe-89") == lookup("CWE-89")