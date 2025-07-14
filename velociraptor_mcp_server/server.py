"""
Main MCP server implementation.
"""

import json
import logging
from typing import Optional

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from .client import VelociraptorClient
from .config import Config

logger = logging.getLogger(__name__)


# Pydantic models for tool parameters
class AuthenticateArgs(BaseModel):
    """Arguments for authentication tool (no parameters needed)."""

    pass


class GetAgentInfoArgs(BaseModel):
    """Arguments for getting agent information by hostname."""

    hostname: str = Field(..., description="Hostname or FQDN of the client to search for")


class RunVQLQueryArgs(BaseModel):
    """Arguments for running VQL queries."""

    vql: str = Field(..., description="VQL (Velociraptor Query Language) query to execute")
    max_rows: Optional[int] = Field(None, description="Maximum number of rows to return")
    timeout: Optional[int] = Field(None, description="Query timeout in seconds")


class ListLinuxArtifactsArgs(BaseModel):
    """Arguments for listing Linux artifacts (no parameters needed)."""

    pass


class ListWindowsArtifactsArgs(BaseModel):
    """Arguments for listing Windows artifacts (no parameters needed)."""

    pass


class CollectArtifactArgs(BaseModel):
    """Arguments for collecting artifacts from a client."""

    client_id: str = Field(..., description="Velociraptor client ID to target for collection")
    artifact: str = Field(..., description="Name of the Velociraptor artifact to collect")
    parameters: str = Field("", description="Comma-separated string of key='value' pairs to pass to the artifact")


class VelociraptorMCPServer:
    """Main MCP server for Velociraptor integration."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client: Optional[VelociraptorClient] = None
        self.app = FastMCP(name="Velociraptor MCP Server", version="0.1.0")

        # Register tools
        self._register_tools()

    def _get_client(self) -> VelociraptorClient:
        """Get or create Velociraptor client."""
        if self._client is None:
            self._client = VelociraptorClient(self.config.velociraptor)
        return self._client

    def _register_tools(self) -> None:
        """Register all available tools."""

        if "AuthenticateTool" not in self.config.server.disabled_tools:

            @self.app.tool(
                name="AuthenticateTool",
                description="Initialize and test connection to Velociraptor server. This tool requires no parameters and will establish a gRPC connection for subsequent API calls using the api.config.yaml file.",
            )
            async def authenticate_tool(args: AuthenticateArgs):
                """Initialize and test connection to Velociraptor server.

                This tool does not require any parameters. Simply call it to initialize
                the gRPC connection and test authentication with the Velociraptor server
                using the configured api.config.yaml file.

                Returns:
                    Success message with connection details or error message.
                """
                try:
                    client = self._get_client()
                    result = await client.authenticate()
                    return [
                        {
                            "type": "text",
                            "text": f"Authentication successful: {json.dumps(result, indent=2)}",
                        },
                    ]
                except Exception as e:
                    logger.error("Authentication failed: %s", e)
                    return [{"type": "text", "text": f"Authentication failed: {str(e)}"}]

        if "GetAgentInfo" not in self.config.server.disabled_tools:

            @self.app.tool(
                name="GetAgentInfo",
                description="Retrieve detailed information about a Velociraptor client by hostname or FQDN. This tool searches for a client using the provided hostname and returns comprehensive client details including ID, OS information, agent version, and connection status.",
            )
            async def get_agent_info_tool(args: GetAgentInfoArgs):
                """Return detailed information about a Velociraptor client by hostname.

                This tool searches for a client using the provided hostname or FQDN and returns
                detailed information including client ID, operating system details, agent version,
                and last seen timestamps.

                Args:
                    args: An object containing:
                        - hostname (required): Hostname or FQDN to search for

                Example usage:
                    {"args": {"hostname": "workstation-01"}}
                    {"args": {"hostname": "server.domain.com"}}

                Returns:
                    JSON object with client details or error message if not found.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # Use the find_client_info method from the client
                    client_info = client.find_client_info(args.hostname)

                    if client_info is None:
                        return [
                            {
                                "type": "text",
                                "text": f"No client found with hostname: {args.hostname}",
                            },
                        ]

                    # Format the response
                    response_text = json.dumps(client_info, indent=2)

                    return [
                        {
                            "type": "text",
                            "text": f"Client information for '{args.hostname}':\n{response_text}",
                        },
                    ]
                except Exception as e:
                    logger.error("Failed to get agent info: %s", e)
                    return [{"type": "text", "text": f"Error getting agent info: {str(e)}"}]

        if "RunVQLQueryTool" not in self.config.server.disabled_tools:

            @self.app.tool(
                name="RunVQLQueryTool",
                description="Execute a VQL (Velociraptor Query Language) query on the Velociraptor server. This tool allows you to run custom VQL queries to retrieve information about clients, artifacts, hunts, or any other Velociraptor data. Requires 'vql' parameter with the query string.",
            )
            async def run_vql_query_tool(args: RunVQLQueryArgs):
                """Execute a VQL query on the Velociraptor server.

                VQL (Velociraptor Query Language) is a powerful query language that allows you to:
                - List and search clients: SELECT * FROM clients()
                - Query artifacts: SELECT * FROM source(artifact='Windows.System.Users')
                - Check flows: SELECT * FROM flows()
                - Hunt management: SELECT * FROM hunts()
                - And much more...

                Args:
                    args: An object containing:
                        - vql (required): VQL query string to execute
                        - max_rows (optional): Maximum number of rows to return
                        - timeout (optional): Query timeout in seconds

                Example usage:
                    {"args": {"vql": "SELECT client_id, os_info.hostname FROM clients() LIMIT 10"}}
                    {"args": {"vql": "SELECT * FROM flows() WHERE client_id = 'C.1234567890'"}}
                    {"args": {"vql": "SELECT name, description FROM artifacts() WHERE name =~ 'Windows'"}}

                Returns:
                    JSON array of query results with columns and data as returned by Velociraptor.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # Execute the VQL query using the client's run_vql_query method
                    results = client.run_vql_query(args.vql)

                    # Format the response
                    response_text = json.dumps(results, indent=2)

                    return [
                        {
                            "type": "text",
                            "text": self._safe_truncate(response_text),
                        },
                    ]
                except Exception as e:
                    logger.error("Failed to execute VQL query: %s", e)
                    return [{"type": "text", "text": f"Error executing VQL query: {str(e)}"}]

        if "ListLinuxArtifactsTool" not in self.config.server.disabled_tools:

            @self.app.tool(
                name="ListLinuxArtifactsTool",
                description="List available Linux artifacts in Velociraptor. This tool returns a summary of all Linux client artifacts including their names, descriptions, and required parameters.",
            )
            async def list_linux_artifacts_tool(args: ListLinuxArtifactsArgs):
                """List available Linux artifacts with their descriptions and parameters.

                This tool queries the Velociraptor server for all available Linux client artifacts
                and returns a structured summary including artifact names, short descriptions,
                and parameter requirements.

                Returns:
                    JSON array of Linux artifacts with name, short_description, and parameters.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # VQL query to get Linux artifacts
                    vql = """
                    LET params(data) = SELECT name FROM data
                    SELECT name, description, params(data=parameters) AS parameters
                    FROM artifact_definitions()
                    WHERE type =~ 'client' AND name =~ 'linux\\.'
                    """

                    # Helper function to shorten descriptions
                    def shorten(desc: str) -> str:
                        return desc.strip().split(".")[0][:120].rstrip() + "..." if desc else ""

                    # Execute the VQL query
                    results = client.run_vql_query(vql)

                    # Process results to create summaries
                    summaries = []
                    for r in results:
                        summaries.append(
                            {
                                "name": r["name"],
                                "short_description": shorten(r.get("description", "")),
                                "parameters": [p["name"] for p in r.get("parameters", [])],
                            },
                        )

                    # Format the response
                    response_text = json.dumps(summaries, indent=2)

                    return [
                        {
                            "type": "text",
                            "text": self._safe_truncate(response_text),
                        },
                    ]
                except Exception as e:
                    logger.error("Failed to list Linux artifacts: %s", e)
                    return [{"type": "text", "text": f"Error listing Linux artifacts: {str(e)}"}]

        if "ListWindowsArtifactsTool" not in self.config.server.disabled_tools:

            @self.app.tool(
                name="ListWindowsArtifactsTool",
                description="List available Windows artifacts in Velociraptor. This tool returns a summary of all Windows client artifacts including their names, descriptions, and required parameters. Generally parameters that target filename regexs are more performant in NTFS queries: MFT, USN and can also be used to target top level folders. A Path glob is performant, and path regex is useful to specifically filter locations.",
            )
            async def list_windows_artifacts_tool(args: ListWindowsArtifactsArgs):
                """List available Windows artifacts with their descriptions and parameters.

                This tool queries the Velociraptor server for all available Windows client artifacts
                and returns a structured summary including artifact names, short descriptions,
                and parameter requirements.

                Generally parameters that target filename regexs are more performant in NTFS queries:
                MFT, USN and can also be used to target top level folders. A Path glob is performant,
                and path regex is useful to specifically filter locations.

                Returns:
                    JSON array of Windows artifacts with name, short_description, and parameters.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # VQL query to get Windows artifacts
                    vql = """
                    LET params(data) = SELECT name FROM data
                    SELECT name, description, params(data=parameters) AS parameters
                    FROM artifact_definitions()
                    WHERE type =~ 'client' AND name =~ '^windows\\.'
                    """

                    # Helper function to shorten descriptions
                    def shorten(desc: str) -> str:
                        return desc.strip().split(".")[0][:120].rstrip() + "..." if desc else ""

                    # Execute the VQL query
                    results = client.run_vql_query(vql)

                    # Process results to create summaries
                    summaries = []
                    for r in results:
                        summaries.append(
                            {
                                "name": r["name"],
                                "short_description": shorten(r.get("description", "")),
                                "parameters": [p["name"] for p in r.get("parameters", [])],
                            },
                        )

                    # Format the response
                    response_text = json.dumps(summaries, indent=2)

                    return [
                        {
                            "type": "text",
                            "text": self._safe_truncate(response_text),
                        },
                    ]
                except Exception as e:
                    logger.error("Failed to list Windows artifacts: %s", e)
                    return [{"type": "text", "text": f"Error listing Windows artifacts: {str(e)}"}]

        if "CollectArtifactTool" not in self.config.server.disabled_tools:

            @self.app.tool(
                name="CollectArtifactTool",
                description="Collect a Velociraptor artifact from a client. This tool allows you to collect specific artifacts from a target client by specifying the client ID and artifact name. Optionally, you can provide parameters for the artifact collection.",
            )
            async def collect_artifact_tool(args: CollectArtifactArgs):
                """Collect a Velociraptor artifact from a client.

                This tool collects a specific artifact from a target client. You must provide
                the client ID and artifact name. Optionally, you can provide parameters for
                the artifact collection in the form of key='value' pairs.

                Args:
                    args: An object containing:
                        - client_id (required): Velociraptor client ID to target for collection
                        - artifact (required): Name of the Velociraptor artifact to collect
                        - parameters (optional): Comma-separated string of key='value' pairs

                Example usage:
                    {"args": {"client_id": "C.1234567890", "artifact": "Windows.System.Users"}}
                    {"args": {"client_id": "C.0987654321", "artifact": "Linux.System.Uptime", "parameters": "format='seconds'"}}

                Returns:
                    JSON object with collection information including flow_id and status.
                """
                try:
                    client = self._get_client()

                    # Ensure client is authenticated
                    if client.stub is None:
                        await client.authenticate()

                    # Start the collection using the client's start_collection method
                    response = client.start_collection(args.client_id, args.artifact, args.parameters)

                    # Ensure the response contains the flow ID
                    if not isinstance(response, list) or not response or "flow_id" not in response[0]:
                        return [
                            {
                                "type": "text",
                                "text": f"Failed to start collection: {json.dumps(response, indent=2)}",
                            },
                        ]

                    # Format the response
                    response_text = json.dumps(response[0], indent=2)

                    return [
                        {
                            "type": "text",
                            "text": f"Collection started successfully:\n{response_text}",
                        },
                    ]
                except Exception as e:
                    logger.error("Failed to collect artifact: %s", e)
                    return [{"type": "text", "text": f"Error collecting artifact: {str(e)}"}]

    def _safe_truncate(self, text: str, max_length: int = 32000) -> str:
        """Truncate text to avoid overwhelming the client."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + f"\n\n[... truncated {len(text) - max_length} characters ...]"

    def _normalize_args(self, raw_args, model_class):
        """Normalize arguments to handle both direct and wrapped formats."""
        if isinstance(raw_args, dict):
            # If it has an 'args' key, use that
            if "args" in raw_args:
                return model_class(**raw_args["args"])
            # Otherwise, assume the dict itself contains the arguments
            else:
                return model_class(**raw_args)
        # If it's already a model instance, return as-is
        elif hasattr(raw_args, "__dict__"):
            return raw_args
        else:
            # Fallback to empty model
            return model_class()

    def start(self, host: str = None, port: int = None) -> None:
        """Start the MCP server."""
        import uvicorn

        host = host or self.config.server.host
        port = port or self.config.server.port

        logger.info("Starting Velociraptor MCP Server on %s:%d", host, port)
        logger.info("SSL Verify: %s", self.config.velociraptor.ssl_verify)

        # Start server with SSE transport
        uvicorn.run(
            self.app.sse_app,
            host=host,
            port=port,
            log_level=self.config.server.log_level.lower(),
        )

    async def close(self) -> None:
        """Close the server and cleanup resources."""
        if self._client:
            await self._client.close()


def create_server(config: Config = None) -> VelociraptorMCPServer:
    """Factory function to create a VelociraptorMCPServer instance."""
    if config is None:
        config = Config.from_env()

    config.validate()
    config.setup_logging()

    return VelociraptorMCPServer(config)
