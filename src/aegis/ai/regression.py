"""A tiny labelled corpus + scorer to measure whether a prompt change helps or hurts.

Every prompt edit this project made was flying blind — one true positive (owncloud) is
not enough to know if a change improved recall or wrecked precision. This is the
harness: a small set of labelled code snippets (each clearly a vulnerability or clearly
clean), a classifier that runs the generator over them, and precision/recall/accuracy so
a prompt change can be judged, not guessed.

All snippets are original, minimal, and synthetic — written to isolate one decision each
(is there a real, reachable bug or not), not copied from anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Case:
    name: str
    language: str
    content: str
    is_vuln: bool          # ground truth
    note: str = ""


# Positives must be flagged; negatives must NOT. Each isolates one judgement.
CASES: tuple[Case, ...] = (
    Case("idor-unscoped", "js",
         "app.get('/invoice/:id', auth, (req,res)=>{\n"
         "  const inv = Invoice.findById(req.params.id);  // no owner/tenant filter\n"
         "  res.json(inv);\n});", True, "IDOR: lookup by request id, no ownership check"),
    Case("idor-scoped", "js",
         "app.get('/invoice/:id', auth, (req,res)=>{\n"
         "  const inv = Invoice.findOne({_id:req.params.id, owner:req.user.id});\n"
         "  res.json(inv);\n});", False, "ownership-scoped lookup — clean"),
    Case("sqli-concat", "php",
         "$id = $_GET['id'];\n"
         "$r = mysqli_query($db, \"SELECT * FROM u WHERE id=\".$id);", True,
         "string-concatenated SQL from request input"),
    Case("sqli-parameterized", "php",
         "$id = $_GET['id'];\n"
         "$s = $db->prepare('SELECT * FROM u WHERE id=?');\n$s->execute([$id]);", False,
         "prepared statement — clean"),
    Case("auth-sibling-gap", "js",
         "router.post('/admin/users', requireAdmin, createUser);\n"
         "router.delete('/admin/users/:id', deleteUser);  // no requireAdmin", True,
         "sibling route drops the admin guard its twin has"),
    Case("auth-consistent", "js",
         "router.post('/admin/users', requireAdmin, createUser);\n"
         "router.delete('/admin/users/:id', requireAdmin, deleteUser);", False,
         "both siblings guarded — clean"),
    Case("ssrf-user-url", "js",
         "app.post('/fetch', auth, (req,res)=>{\n"
         "  return fetch(req.body.url).then(r=>r.text()).then(t=>res.send(t));\n});", True,
         "outbound request to a user-controlled URL"),
    Case("intended-admin", "js",
         "// admins may read any user's profile by design\n"
         "app.get('/admin/user/:id', requireAdmin, (req,res)=>res.json(getUser(req.params.id)));",
         False, "admin-only by design — intended functionality, not a bug"),
    Case("csrf-preauth-token", "php",
         "// public share accept, gated by the secret invite token from the email link\n"
         "function acceptInvite(){ $u = getUserByInviteToken($_GET['token']); ... }", False,
         "pre-auth flow gated by a secret token — CSRF does not apply"),
    Case("dom-xss", "js",
         "el.innerHTML = location.hash.slice(1);  // untrusted fragment into innerHTML",
         True, "DOM XSS: untrusted fragment to innerHTML"),
)


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return round(self.tp / d, 3) if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return round(self.tp / d, 3) if d else 0.0

    @property
    def accuracy(self) -> float:
        return round((self.tp + self.tn) / self.total, 3) if self.total else 0.0

    def as_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "precision": self.precision, "recall": self.recall,
                "accuracy": self.accuracy, "total": self.total}


def evaluate(classify, cases: tuple[Case, ...] = CASES) -> tuple[Metrics, list[dict]]:
    """Run ``classify(content, language) -> bool`` over the cases and score it.
    Returns the metrics and the per-case results (with the misses flagged)."""
    m = Metrics()
    detail: list[dict] = []
    for case in cases:
        try:
            predicted = bool(classify(case.content, case.language))
        except Exception:
            predicted = False
        correct = predicted == case.is_vuln
        if case.is_vuln and predicted:
            m.tp += 1
        elif case.is_vuln and not predicted:
            m.fn += 1
        elif not case.is_vuln and predicted:
            m.fp += 1
        else:
            m.tn += 1
        detail.append({"name": case.name, "expected_vuln": case.is_vuln,
                       "predicted_vuln": predicted, "correct": correct, "note": case.note})
    return m, detail


def make_classifier(client, **agent_kwargs):
    """A classifier backed by the real generator: flags a case if the agent returns any
    hypothesis for it. ``agent_kwargs`` lets a caller test prompt/config variants."""
    from .agents.contracts import AgentKind, AgentTask, SourceSlice
    from .agents.runner import SpecializedAgent

    _EXT = {"js": ".js", "ts": ".ts", "php": ".php", "py": ".py", "go": ".go",
            "sol": ".sol", "rb": ".rb", "java": ".java"}

    def classify(content: str, language: str) -> bool:
        path = f"case{_EXT.get(language, '.txt')}"
        task = AgentTask(kind=AgentKind.AUTHORIZATION, target="regression:" + path,
                         source_slices=[SourceSlice(path=path, content=content)],
                         policy_notes="Authorized static review of a code snippet.")
        return bool(SpecializedAgent(client, require_reachability=True, **agent_kwargs).analyze(task))

    return classify
