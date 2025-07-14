"""
Tests for Velociraptor client.
"""

import json
from unittest.mock import AsyncMock, Mock, mock_open, patch

import pytest

from velociraptor_mcp_server.client import VelociraptorClient


class TestVelociraptorClient:
    """Test Velociraptor client."""

    def test_init(self, velociraptor_config):
        """Test VelociraptorClient initialization."""
        client = VelociraptorClient(velociraptor_config)

        assert client.config == velociraptor_config
        assert client.stub is None

    @pytest.mark.asyncio
    async def test_authenticate_success(self, velociraptor_client, mock_grpc_client):
        """Test successful authentication."""
        # Mock the authentication process
        mock_query_response = Mock()
        mock_query_response.Response = json.dumps([{"user": "test_user", "permissions": ["READ"]}])
        mock_query_response.error = None  # No error

        # Make the Query return an iterable
        mock_grpc_client.Query.return_value = [mock_query_response]

        with patch("grpc.ssl_channel_credentials"), patch("grpc.secure_channel"), patch(
            "velociraptor_mcp_server.client.api_pb2_grpc.APIStub",
            return_value=mock_grpc_client,
        ), patch(
            "yaml.safe_load",
            return_value={
                "ca_certificate": "test_ca_cert",
                "client_cert": "test_client_cert",
                "client_private_key": "test_private_key",
                "api_connection_string": "localhost:8001",
            },
        ), patch(
            "builtins.open",
            mock_open(),
        ), patch(
            "os.path.exists",
            return_value=True,
        ):
            result = await velociraptor_client.authenticate()

            assert result["status"] == "authenticated"
            assert result["connection_type"] == "gRPC"
            assert "test_query_result" in result
            assert len(result["test_query_result"]) == 1
            assert result["test_query_result"][0]["user"] == "test_user"
            assert velociraptor_client.stub is not None

    @pytest.mark.asyncio
    async def test_authenticate_file_not_found(self, velociraptor_client):
        """Test authentication when config file is not found."""
        with patch("builtins.open", side_effect=FileNotFoundError("Config file not found")):
            with pytest.raises(Exception):
                await velociraptor_client.authenticate()

    def test_run_vql_query_success(self, velociraptor_client, mock_grpc_client):
        """Test successful VQL query execution."""
        # Set up authenticated client
        velociraptor_client.stub = mock_grpc_client

        # Mock VQL query response
        mock_query_response = Mock()
        mock_query_response.Response = json.dumps(
            [
                {"client_id": "C.1234567890", "hostname": "test-host"},
                {"client_id": "C.0987654321", "hostname": "test-host-2"},
            ],
        )
        mock_query_response.error = None  # No error

        mock_grpc_client.Query.return_value = [mock_query_response]

        result = velociraptor_client.run_vql_query("SELECT * FROM clients() LIMIT 10")

        assert len(result) == 2
        assert result[0]["client_id"] == "C.1234567890"
        assert result[1]["hostname"] == "test-host-2"

    def test_run_vql_query_not_authenticated(self, velociraptor_client):
        """Test VQL query when client is not authenticated."""
        # Client stub is None (not authenticated)
        assert velociraptor_client.stub is None

        with pytest.raises(Exception):
            velociraptor_client.run_vql_query("SELECT * FROM clients()")

    def test_find_client_info_success(self, velociraptor_client, mock_grpc_client):
        """Test successful client info lookup by hostname."""
        # Set up authenticated client
        velociraptor_client.stub = mock_grpc_client

        # Mock VQL query response for client search
        mock_query_response = Mock()
        mock_query_response.Response = json.dumps(
            [
                {
                    "client_id": "C.1234567890",
                    "FirstSeen": "2023-01-01T00:00:00Z",
                    "LastSeen": "2023-01-02T00:00:00Z",
                    "Hostname": "test-host",
                    "Fqdn": "test-host.domain.com",
                    "OSType": "Linux",
                    "OS": "Ubuntu 20.04",
                    "Machine": "x86_64",
                    "AgentVersion": "0.72.0",
                },
            ],
        )
        mock_query_response.error = None  # No error

        mock_grpc_client.Query.return_value = [mock_query_response]

        result = velociraptor_client.find_client_info("test-host")

        assert result is not None
        assert result["client_id"] == "C.1234567890"
        assert result["Hostname"] == "test-host"
        assert result["OSType"] == "Linux"

    def test_find_client_info_not_found(self, velociraptor_client, mock_grpc_client):
        """Test client info lookup when client is not found."""
        # Set up authenticated client
        velociraptor_client.stub = mock_grpc_client

        # Mock empty VQL query response
        mock_query_response = Mock()
        mock_query_response.Response = json.dumps([])
        mock_query_response.error = None  # No error

        mock_grpc_client.Query.return_value = [mock_query_response]

        result = velociraptor_client.find_client_info("nonexistent-host")

        assert result is None

    def test_start_collection_success(self, velociraptor_client, mock_grpc_client):
        """Test successful collection start."""
        # Set up authenticated client
        velociraptor_client.stub = mock_grpc_client

        # Mock collection start response
        mock_query_response = Mock()
        mock_query_response.Response = json.dumps(
            [{"flow_id": "F.1234567890", "status": "RUNNING"}],
        )
        mock_query_response.error = None  # No error

        mock_grpc_client.Query.return_value = [mock_query_response]

        result = velociraptor_client.start_collection("C.1234567890", "Windows.System.Users")

        assert len(result) == 1
        assert result[0]["flow_id"] == "F.1234567890"
        assert result[0]["status"] == "RUNNING"

    def test_close(self, velociraptor_client):
        """Test client close method."""
        # Mock channel
        mock_channel = Mock()
        mock_channel.close = Mock()
        velociraptor_client._channel = mock_channel

        velociraptor_client.close()

        mock_channel.close.assert_called_once()
