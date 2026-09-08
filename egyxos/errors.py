"""Stable, machine-readable errors used by the CLI and integrations."""


class EgyxosError(Exception):
    """Base exception with a stable error code."""

    code = "egyxos_error"

    def __init__(self, message: str, *, details=None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def as_dict(self):
        return {"error": self.code, "message": self.message, "details": self.details}


class AuthorizationError(EgyxosError):
    code = "authorization_required"


class ScopeError(EgyxosError):
    code = "invalid_scope"


class ToolNotFoundError(EgyxosError):
    code = "tool_not_found"


class ToolExecutionError(EgyxosError):
    code = "tool_execution_failed"


class ConfigurationError(EgyxosError):
    code = "configuration_error"
