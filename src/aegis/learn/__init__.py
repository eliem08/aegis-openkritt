"""The learning loop — the system improves itself from outcomes.

Human verdicts on findings (and later, submission results) are recorded as
:class:`~aegis.learn.store.Outcome` objects. Two things read that store and update
automatically, with no retraining:

* **Calibration** (:class:`~aegis.learn.calibration.Calibration`) turns verdicts
  into per-detector / per-CWE precision priors that reweight candidate ranking.
* **Retrieval memory** (:func:`~aegis.learn.memory.learned_context`,
  :class:`~aegis.learn.memory.PlannerKnowledge`) feeds the DeepSeek planner few-shot
  examples of what panned out, so it plans better in-context.

This is genuine auto-learning without fine-tuning: as verdicts accumulate, both the
ranking and the LLM's plans shift toward what has actually worked.
"""

from .calibration import Calibration
from .memory import PlannerKnowledge, learned_context, recall
from .store import Outcome, OutcomeStore, Verdict

__all__ = [
    "Outcome",
    "OutcomeStore",
    "Verdict",
    "Calibration",
    "recall",
    "learned_context",
    "PlannerKnowledge",
]
