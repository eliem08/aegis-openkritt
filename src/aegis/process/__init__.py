"""Safe external-process execution (Master Prompt §6).

Runs tools as argv arrays with bounded resources, minimal env, secrets kept out
of argv, streamed output, and full process-tree termination. See
:class:`SafeProcessRunner`.
"""

from .container import (
    ContainerLimits,
    ContainerPolicyError,
    HardenedDockerCommandBuilder,
    ReadOnlyMount,
)
from .runner import (
    BinaryVerificationError,
    CancelToken,
    ProcessLimits,
    ProcessOutcome,
    ProcessResult,
    SafeProcessRunner,
    verify_binary,
)

__all__ = [
    "SafeProcessRunner",
    "ProcessLimits",
    "ProcessResult",
    "ProcessOutcome",
    "CancelToken",
    "verify_binary",
    "BinaryVerificationError",
    "ContainerLimits",
    "ContainerPolicyError",
    "HardenedDockerCommandBuilder",
    "ReadOnlyMount",
]
