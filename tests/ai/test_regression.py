"""Labelled regression corpus + scorer."""

from __future__ import annotations

from aegis.ai.regression import CASES, Metrics, evaluate, make_classifier


def test_corpus_is_balanced_and_labelled():
    pos = sum(1 for c in CASES if c.is_vuln)
    neg = len(CASES) - pos
    assert pos >= 4 and neg >= 4                          # both classes represented
    assert all(c.name and c.content and c.note for c in CASES)


def test_perfect_classifier_scores_1():
    # an oracle that knows the labels
    labels = {c.content: c.is_vuln for c in CASES}
    m, detail = evaluate(lambda content, lang: labels[content])
    assert m.precision == 1.0 and m.recall == 1.0 and m.accuracy == 1.0
    assert all(d["correct"] for d in detail)


def test_always_false_has_zero_recall_but_no_false_positives():
    m, _ = evaluate(lambda content, lang: False)
    assert m.recall == 0.0 and m.fp == 0 and m.tp == 0


def test_always_true_flags_everything():
    m, _ = evaluate(lambda content, lang: True)
    assert m.fp > 0 and m.fn == 0                         # catches all vulns, but noisy


def test_metrics_math():
    m = Metrics(tp=3, fp=1, tn=4, fn=2)
    assert m.precision == 0.75 and m.recall == 0.6 and m.total == 10


def test_make_classifier_uses_the_agent():
    # a fake client that flags only the idor case by its content marker
    class _Client:
        def complete_json(self, messages, **kwargs):
            user = messages[1]["content"]
            if "findById(req.params.id)" in user:
                return {"hypotheses": [{
                    "weakness": "CWE-639", "title": "idor", "file_path": "case.js",
                    "line": 2, "rationale": "no owner check", "confidence": 0.7,
                    "entry_point": "GET /invoice/:id", "attacker": "any user",
                    "impact": "reads another user's invoice", "severity": "high",
                    "verification": {"method": "static_analysis",
                                     "expected_observation": "o", "maximum_requests": 0}}]}
            return {"hypotheses": []}
    classify = make_classifier(_Client())
    m, detail = evaluate(classify)
    # it flagged the idor positive; find that case correct
    idor = next(d for d in detail if d["name"] == "idor-unscoped")
    assert idor["predicted_vuln"] is True and idor["correct"] is True
