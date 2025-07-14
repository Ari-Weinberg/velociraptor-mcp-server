"""
Tests for the main server.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from velociraptor_mcp_server.config import Config
from velociraptor_mcp_server.server import VelociraptorMCPServer, create_server


class TestVelociraptorMCPServer:
    """args = RunVQLQueryArgs(vql="SELECT * FROM clients() LIMIT 5")

    # Execute the tool
    result = await run_vql_query_tool.run(args) Velociraptor MCP server."""

    def test_init(self, config):
        """Test VelociraptorMCPServer initialization."""
        server = VelociraptorMCPServer(config)

        assert server.config == config
        assert server._client is None
        assert server.app is not None
        assert server.app.name == "Velociraptor MCP Server"

    def test_get_client(self, config):
        """Test _get_client method."""
        server = VelociraptorMCPServer(config)

        # First call should create client
        client1 = server._get_client()
        assert client1 is not None
        assert server._client is client1

        # Second call should return same client
        client2 = server._get_client()
        assert client2 is client1

    def test_safe_truncate_short_text(self, config):
        """Test _safe_truncate with short text."""
        server = VelociraptorMCPServer(config)

        short_text = "This is a short text"
        result = server._safe_truncate(short_text)

        assert result == short_text

    def test_safe_truncate_long_text(self, config):
        """Test _safe_truncate with long text."""
        server = VelociraptorMCPServer(config)

        long_text = "A" * 50000  # 50k characters
        result = server._safe_truncate(long_text, max_length=1000)

        assert len(result) > 1000  # Should include truncation message
        assert result.startswith("A" * 1000)
        assert "truncated" in result

    @pytest.mark.asyncio
    async def test_close(self, config):
        """Test server close method."""
        server = VelociraptorMCPServer(config)

        # Mock client
        mock_client = Mock()
        mock_client.close = AsyncMock()
        server._client = mock_client

        await server.close()

        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_no_client(self, config):
        """Test server close method with no client."""
        server = VelociraptorMCPServer(config)

        # Should not raise an exception
        await server.close()

    @pytest.mark.asyncio
    async def test_authenticate_tool_registration(self, config):
        """Test that AuthenticateTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "AuthenticateTool" in tool_names

    @pytest.mark.asyncio
    async def test_authenticate_tool_disabled(self, config):
        """Test that AuthenticateTool is not registered when disabled."""
        config.server.disabled_tools = ["AuthenticateTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "AuthenticateTool" not in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_registration(self, config):
        """Test that GetAgentInfo is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentInfo" in tool_names

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_disabled(self, config):
        """Test that GetAgentInfo is not registered when disabled."""
        config.server.disabled_tools = ["GetAgentInfo"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "GetAgentInfo" not in tool_names

    @pytest.mark.asyncio
    async def test_run_vql_query_tool_registration(self, config):
        """Test that RunVQLQueryTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "RunVQLQueryTool" in tool_names

    @pytest.mark.asyncio
    async def test_run_vql_query_tool_disabled(self, config):
        """Test that RunVQLQueryTool is not registered when disabled."""
        config.server.disabled_tools = ["RunVQLQueryTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "RunVQLQueryTool" not in tool_names

    @pytest.mark.asyncio
    async def test_list_linux_artifacts_tool_registration(self, config):
        """Test that ListLinuxArtifactsTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListLinuxArtifactsTool" in tool_names

    @pytest.mark.asyncio
    async def test_list_linux_artifacts_tool_disabled(self, config):
        """Test that ListLinuxArtifactsTool is not registered when disabled."""
        config.server.disabled_tools = ["ListLinuxArtifactsTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListLinuxArtifactsTool" not in tool_names

    @pytest.mark.asyncio
    async def test_list_windows_artifacts_tool_registration(self, config):
        """Test that ListWindowsArtifactsTool is registered when not disabled."""
        server = VelociraptorMCPServer(config)

        # Check that the tool is registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListWindowsArtifactsTool" in tool_names

    @pytest.mark.asyncio
    async def test_list_windows_artifacts_tool_disabled(self, config):
        """Test that ListWindowsArtifactsTool is not registered when disabled."""
        config.server.disabled_tools = ["ListWindowsArtifactsTool"]
        server = VelociraptorMCPServer(config)

        # Check that the tool is not registered
        tools = await server.app.get_tools()
        tool_names = list(tools.keys())
        assert "ListWindowsArtifactsTool" not in tool_names

    @pytest.mark.asyncio
    async def test_authenticate_tool_execution(self, config):
        """Test AuthenticateTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.authenticate = AsyncMock(
            return_value={"status": "authenticated", "user": "test_user"},
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        authenticate_tool = tools["AuthenticateTool"]

        # Execute the tool
        result = await authenticate_tool.run({"args": {}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        assert "Authentication successful" in result.content[0].text
        mock_client.authenticate.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_execution_success(self, config):
        """Test GetAgentInfo execution with successful result."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.find_client_info = Mock(
            return_value={
                "client_id": "C.1234567890",
                "hostname": "test-host",
                "os_info": {"system": "Linux", "release": "Ubuntu 20.04"},
            },
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_agent_info_tool = tools["GetAgentInfo"]

        # Execute the tool
        result = await get_agent_info_tool.run({"args": {"hostname": "test-host"}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        assert "Client information for 'test-host'" in result.content[0].text
        assert "C.1234567890" in result.content[0].text
        mock_client.find_client_info.assert_called_once_with("test-host")

    @pytest.mark.asyncio
    async def test_get_agent_info_tool_execution_not_found(self, config):
        """Test GetAgentInfo execution when client not found."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.find_client_info = Mock(return_value=None)
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        get_agent_info_tool = tools["GetAgentInfo"]

        # Execute the tool
        result = await get_agent_info_tool.run({"args": {"hostname": "nonexistent-host"}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        assert "No client found with hostname: nonexistent-host" in result.content[0].text
        mock_client.find_client_info.assert_called_once_with("nonexistent-host")

    @pytest.mark.asyncio
    async def test_run_vql_query_tool_execution(self, config):
        """Test RunVQLQueryTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(
            return_value=[
                {"client_id": "C.1234567890", "hostname": "test-host"},
                {"client_id": "C.0987654321", "hostname": "test-host-2"},
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        run_vql_query_tool = tools["RunVQLQueryTool"]

        # Execute the tool
        result = await run_vql_query_tool.run({"args": {"vql": "SELECT * FROM clients() LIMIT 10"}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        # The result.content[0].text contains a JSON array with one element that has the actual data
        outer_data = json.loads(result.content[0].text)
        assert len(outer_data) == 1
        result_data = json.loads(outer_data[0]["text"])
        assert len(result_data) == 2
        assert result_data[0]["client_id"] == "C.1234567890"
        mock_client.run_vql_query.assert_called_once_with("SELECT * FROM clients() LIMIT 10")

    @pytest.mark.asyncio
    async def test_list_linux_artifacts_tool_execution(self, config):
        """Test ListLinuxArtifactsTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Linux.System.Info",
                    "description": "Gather basic system information from a Linux system. This includes OS version, kernel info, and hardware details.",
                    "parameters": [{"name": "param1"}, {"name": "param2"}],
                },
                {
                    "name": "Linux.Network.Netstat",
                    "description": "Parse netstat output to show network connections and listening ports.",
                    "parameters": [{"name": "connection_type"}],
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        list_linux_artifacts_tool = tools["ListLinuxArtifactsTool"]

        # Execute the tool
        result = await list_linux_artifacts_tool.run({"args": {}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        # The result.content[0].text contains a JSON array with one element that has the actual data
        outer_data = json.loads(result.content[0].text)
        assert len(outer_data) == 1
        response_data = json.loads(outer_data[0]["text"])

        # Check that we have the expected artifacts
        assert len(response_data) == 2
        assert response_data[0]["name"] == "Linux.System.Info"
        assert "Gather basic system information" in response_data[0]["short_description"]
        assert response_data[0]["parameters"] == ["param1", "param2"]

        assert response_data[1]["name"] == "Linux.Network.Netstat"
        assert "Parse netstat output" in response_data[1]["short_description"]
        assert response_data[1]["parameters"] == ["connection_type"]

        # Verify the VQL query was called
        mock_client.run_vql_query.assert_called_once()
        called_vql = mock_client.run_vql_query.call_args[0][0]
        assert "artifact_definitions()" in called_vql
        assert "linux\\." in called_vql

    @pytest.mark.asyncio
    async def test_list_windows_artifacts_tool_execution(self, config):
        """Test ListWindowsArtifactsTool execution."""
        server = VelociraptorMCPServer(config)

        # Mock the client
        mock_client = Mock()
        mock_client.stub = Mock()  # Simulate authenticated client
        mock_client.authenticate = AsyncMock()
        mock_client.run_vql_query = Mock(
            return_value=[
                {
                    "name": "Windows.System.Services",
                    "description": "List all installed Windows services with their configuration and status. This includes service name, display name, and current state.",
                    "parameters": [{"name": "service_name"}, {"name": "status_filter"}],
                },
                {
                    "name": "Windows.Registry.NTUser",
                    "description": "Parse NTUSER.DAT registry hive files to extract user-specific registry keys.",
                    "parameters": [{"name": "key_path"}],
                },
            ],
        )
        server._client = mock_client

        # Get the tool and execute it
        tools = await server.app.get_tools()
        list_windows_artifacts_tool = tools["ListWindowsArtifactsTool"]

        # Execute the tool
        result = await list_windows_artifacts_tool.run({"args": {}})

        # Verify result - ToolResult object
        assert hasattr(result, "content")
        assert len(result.content) == 1
        assert hasattr(result.content[0], "text")
        # The result.content[0].text contains a JSON array with one element that has the actual data
        outer_data = json.loads(result.content[0].text)
        assert len(outer_data) == 1
        response_data = json.loads(outer_data[0]["text"])

        # Check that we have the expected artifacts
        assert len(response_data) == 2
        assert response_data[0]["name"] == "Windows.System.Services"
        assert "List all installed Windows services" in response_data[0]["short_description"]
        assert response_data[0]["parameters"] == ["service_name", "status_filter"]

        assert response_data[1]["name"] == "Windows.Registry.NTUser"
        assert "Parse NTUSER" in response_data[1]["short_description"]
        assert response_data[1]["parameters"] == ["key_path"]

        # Verify the VQL query was called
        mock_client.run_vql_query.assert_called_once()
        called_vql = mock_client.run_vql_query.call_args[0][0]
        assert "artifact_definitions()" in called_vql
        assert "^windows\\." in called_vql


class TestCreateServer:
    """Test create_server factory function."""

    def test_create_server_with_config(self, config):
        """Test create_server with provided config."""
        with patch("os.path.exists", return_value=True):
            server = create_server(config)

            assert isinstance(server, VelociraptorMCPServer)
            assert server.config == config

    @patch("velociraptor_mcp_server.server.Config.from_env")
    def test_create_server_without_config(self, mock_from_env, config):
        """Test create_server without config (uses env)."""
        mock_from_env.return_value = config

        with patch("os.path.exists", return_value=True):
            server = create_server()

            assert isinstance(server, VelociraptorMCPServer)
            mock_from_env.assert_called_once()
