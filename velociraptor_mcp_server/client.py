"""
Velociraptor client for API communication.
"""

import json
import logging
import os
import yaml
from typing import Any, Dict, List, Optional

import grpc
from pyvelociraptor import api_pb2, api_pb2_grpc

from .config import VelociraptorConfig
from .exceptions import VelociraptorAPIError, VelociraptorAuthenticationError

logger = logging.getLogger(__name__)


class VelociraptorClient:
    """Client for communicating with Velociraptor API via gRPC."""

    def __init__(self, config: VelociraptorConfig):
        """Initialize the Velociraptor client.

        Args:
            config: Velociraptor configuration object
        """
        self.config = config
        self.stub: Optional[api_pb2_grpc.APIStub] = None
        self._channel: Optional[grpc.Channel] = None

    async def authenticate(self) -> Dict[str, Any]:
        """Initialize gRPC connection and test authentication.

        Returns:
            Dictionary with connection status and server information

        Raises:
            VelociraptorAuthenticationError: If authentication fails
            VelociraptorAPIError: If API connection fails
        """
        try:
            # For Velociraptor, we need to use a config file or API key
            # If config.api_key is a path to a config file, load it
            if self.config.api_key.endswith('.yaml') or self.config.api_key.endswith('.yml'):
                config_path = self.config.api_key
                if not os.path.exists(config_path):
                    raise VelociraptorAuthenticationError(f"Config file not found: {config_path}")

                # Load the API config file
                with open(config_path, 'r') as f:
                    api_config = yaml.safe_load(f)

                # Validate required fields
                required_fields = ["ca_certificate", "client_private_key", "client_cert", "api_connection_string"]
                for field in required_fields:
                    if field not in api_config:
                        raise VelociraptorAuthenticationError(f"Missing required field in config: {field}")

                # Create SSL credentials
                creds = grpc.ssl_channel_credentials(
                    root_certificates=api_config["ca_certificate"].encode("utf-8"),
                    private_key=api_config["client_private_key"].encode("utf-8"),
                    certificate_chain=api_config["client_cert"].encode("utf-8")
                )

                # Channel options
                channel_opts = (('grpc.ssl_target_name_override', "VelociraptorServer"),)

                # Create secure channel
                self._channel = grpc.secure_channel(
                    api_config["api_connection_string"],
                    creds,
                    options=channel_opts
                )

                # Create stub
                self.stub = api_pb2_grpc.APIStub(self._channel)

                # Test the connection with a simple query
                test_request = api_pb2.VQLCollectorArgs(
                    Query=[api_pb2.VQLRequest(VQL="SELECT 'connection_test' as status")]
                )

                # Try to execute a test query
                results = []
                for resp in self.stub.Query(test_request):
                    if hasattr(resp, "error") and resp.error:
                        raise VelociraptorAPIError(f"Velociraptor API error: {resp.error}")
                    if hasattr(resp, "Response") and resp.Response:
                        results.extend(json.loads(resp.Response))

                return {
                    "status": "authenticated",
                    "connection_type": "gRPC",
                    "server_url": api_config["api_connection_string"],
                    "test_query_result": results,
                    "message": "Successfully connected to Velociraptor server"
                }

            else:
                # If it's not a config file path, treat it as a direct API key
                # This would require implementing HTTP API authentication
                # For now, we'll raise an error suggesting to use config file
                raise VelociraptorAuthenticationError(
                    "Direct API key authentication not yet implemented. "
                    "Please provide a path to an api.config.yaml file in the VELOCIRAPTOR_API_KEY environment variable."
                )

        except grpc.RpcError as e:
            logger.error("gRPC error during authentication: %s", e)
            raise VelociraptorAuthenticationError(f"gRPC connection failed: {e}")
        except Exception as e:
            logger.error("Authentication failed: %s", e)
            if isinstance(e, (VelociraptorAuthenticationError, VelociraptorAPIError)):
                raise
            raise VelociraptorAuthenticationError(f"Authentication failed: {e}")

    def run_vql_query(self, vql: str) -> List[Dict[str, Any]]:
        """Execute a VQL query on the Velociraptor server.

        Args:
            vql: VQL query string to execute

        Returns:
            List of result dictionaries

        Raises:
            VelociraptorAPIError: If query execution fails
            RuntimeError: If stub is not initialized
        """
        if self.stub is None:
            raise RuntimeError("Stub not initialized. Call authenticate() first.")

        try:
            request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(VQL=vql)])
            results = []

            for resp in self.stub.Query(request):
                if hasattr(resp, "error") and resp.error:
                    raise VelociraptorAPIError(f"Velociraptor API error: {resp.error}")
                if hasattr(resp, "Response") and resp.Response:
                    results.extend(json.loads(resp.Response))

            return results

        except grpc.RpcError as e:
            logger.error("gRPC error during query execution: %s", e)
            raise VelociraptorAPIError(f"Query execution failed: {e}")
        except Exception as e:
            logger.error("Query execution failed: %s", e)
            raise VelociraptorAPIError(f"Query execution failed: {e}")

    def close(self):
        """Close the gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self.stub = None

    # Helper methods based on the provided examples

    def find_client_info(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Find client information by hostname.

        Args:
            hostname: Hostname to search for

        Returns:
            Client information dictionary or None if not found
        """
        vql = (
            f"SELECT client_id,"
            "timestamp(epoch=first_seen_at) as FirstSeen,"
            "timestamp(epoch=last_seen_at) as LastSeen,"
            "os_info.hostname as Hostname,"
            "os_info.fqdn as Fqdn,"
            "os_info.system as OSType,"
            "os_info.release as OS,"
            "os_info.machine as Machine,"
            "agent_information.version as AgentVersion "
            f"FROM clients() WHERE os_info.hostname =~ '^{hostname}$' OR os_info.fqdn =~ '^{hostname}$' ORDER BY LastSeen DESC LIMIT 1"
        )

        result = self.run_vql_query(vql)
        if not result:
            return None
        return result[0]

    def start_collection(self, client_id: str, artifact: str, parameters: str = "") -> List[Dict[str, Any]]:
        """Start a collection on a client.

        Args:
            client_id: Target client ID
            artifact: Artifact to collect
            parameters: Collection parameters

        Returns:
            Collection information
        """
        vql = (
            f"LET collection <= collect_client(urgent='TRUE',client_id='{client_id}', artifacts='{artifact}', env=dict({parameters})) "
            f"SELECT flow_id,request.artifacts as artifacts,request.specs[0] as specs FROM foreach(row= collection)"
        )

        return self.run_vql_query(vql)

    def get_flow_status(self, client_id: str, flow_id: str, artifact: str) -> str:
        """Get the status of a flow.

        Args:
            client_id: Target client ID
            flow_id: Flow ID to check
            artifact: Artifact name

        Returns:
            Status string: "FINISHED" or "RUNNING"
        """
        vql = (
            f"SELECT * FROM flow_logs(client_id='{client_id}', flow_id='{flow_id}') "
            f"WHERE message =~ '^Collection {artifact} is done after' "
            f"LIMIT 100"
        )

        results = self.run_vql_query(vql)
        if results and isinstance(results, list) and len(results) > 0:
            return "FINISHED"
        return "RUNNING"

    def get_flow_results(self, client_id: str, flow_id: str, artifact: str, fields: str = "*") -> List[Dict[str, Any]]:
        """Get results from a completed flow.

        Args:
            client_id: Target client ID
            flow_id: Flow ID to get results from
            artifact: Artifact name
            fields: Fields to select

        Returns:
            Flow results
        """
        vql = f"SELECT {fields} FROM source(client_id='{client_id}', flow_id='{flow_id}',artifact='{artifact}')"
        return self.run_vql_query(vql)

    def realtime_collection(self, client_id: str, artifact: str, parameters: str = "", fields: str = "*", result_scope: str = "") -> List[Dict[str, Any]]:
        """Perform a realtime collection and wait for results.

        Args:
            client_id: Target client ID
            artifact: Artifact to collect
            parameters: Collection parameters
            fields: Fields to select from results
            result_scope: Additional scope for results

        Returns:
            Collection results
        """
        vql = (
            f"LET collection <= collect_client(urgent='TRUE',client_id='{client_id}', artifacts='{artifact}', env=dict({parameters})) "
            f"LET get_monitoring = SELECT * FROM watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = collection.flow_id LIMIT 1 "
            f"LET get_results = SELECT * FROM source(client_id=collection.request.client_id, flow_id=collection.flow_id,artifact='{artifact}{result_scope}') "
            f"SELECT {fields} FROM foreach(row= get_monitoring ,query= get_results)"
        )

        return self.run_vql_query(vql)

    def __del__(self):
        """Cleanup when object is destroyed."""
        self.close()
