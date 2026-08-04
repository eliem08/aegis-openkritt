"""Heuristic taint source→sink lead extraction."""

from __future__ import annotations

from aegis.ai.taint import extract_flows, taint_hints_text


def test_tracks_request_param_into_sql_sink():
    code = "\n".join([
        "function h(req, res) {",
        "  const id = req.query.id;",
        "  const rows = db.query('SELECT * FROM u WHERE id=' + id);",
        "}",
    ])
    flows = extract_flows(code)
    assert flows
    f = flows[0]
    assert f.carrier == "id" and "sql" in f.sink_class
    assert f.source_line == 2 and f.sink_line == 3


def test_inline_source_at_sink_is_flagged():
    code = "res.send(fetch(req.query.url))"          # source and sink on one line
    flows = extract_flows(code)
    assert flows and "SSRF" in flows[0].sink_class


def test_one_hop_propagation():
    code = "\n".join([
        "let raw = req.body.path;",
        "let p = normalize(raw);",              # p carries taint from raw
        "readFile(p);",
    ])
    flows = extract_flows(code)
    assert any(f.carrier == "p" and "path traversal" in f.sink_class for f in flows)


def test_clean_file_yields_no_flows():
    code = "const x = 1 + 2;\nconsole.log(x);"
    assert extract_flows(code) == []


def test_php_superglobal_source():
    code = "$q = $_GET['q'];\nmysqli_query($db, \"SELECT $q\");"
    flows = extract_flows(code)
    assert flows and flows[0].carrier == "$q"


def test_hints_text_renders_or_empty():
    assert taint_hints_text([]) == ""
    code = "const id=req.query.id;\ndb.query('x'+id)"
    text = taint_hints_text(extract_flows(code))
    assert "Taint leads" in text and "trace and PROVE" in text and "carrier: id" in text


def test_bounded_flow_count():
    code = "\n".join([f"exec(req.query.c{i})" for i in range(50)])
    assert len(extract_flows(code, max_flows=5)) == 5
