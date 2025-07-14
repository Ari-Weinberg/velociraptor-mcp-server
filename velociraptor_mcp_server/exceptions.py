"""
Exception classes for Velociraptor MCP Server.
"""


class VelociraptorMCPError(Exception):
    """Base exception for Velociraptor MCP Server."""

    pass


class VelociraptorAuthenticationError(VelociraptorMCPError):
    """Raised when authentication with Velociraptor fails."""

    pass


class VelociraptorAPIError(VelociraptorMCPError):
    """Raised when Velociraptor API returns an error."""

    pass


class ConfigurationError(VelociraptorMCPError):
    """Raised when configuration is invalid."""

    pass
