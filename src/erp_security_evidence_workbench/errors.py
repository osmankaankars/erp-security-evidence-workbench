"""Expected, safely reportable workbench errors."""


class WorkbenchError(Exception):
    """Base class for expected user-facing failures."""


class InputValidationError(WorkbenchError):
    """Raised when input evidence cannot be accepted safely."""


class IncompleteEvidenceError(WorkbenchError):
    """Raised when evidence coverage cannot support a conclusive result."""


class OutputError(WorkbenchError):
    """Raised when a final report cannot be published safely."""
