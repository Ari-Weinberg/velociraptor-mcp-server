"""
Tests for the main server.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from velociraptor_mcp_server.config import Config
from velociraptor_mcp_server.server import VelociraptorMCPServer, create_server


class TestVelociraptorMCPServer:
    """Test Velociraptor MCP server."""

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

        # Mock arguments
        from velociraptor_mcp_server.server import AuthenticateArgs

        args = AuthenticateArgs()

        # Execute the tool
        result = await authenticate_tool(args)

        # Verify result
        assert len(result) == 1
        assert result[0]["type"] == "text"
        assert "Authentication successful" in result[0]["text"]
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

        # Mock arguments
        from velociraptor_mcp_server.server import GetAgentInfoArgs

        args = GetAgentInfoArgs(hostname="test-host")

        # Execute the tool
        result = await get_agent_info_tool(args)

        # Verify result
        assert len(result) == 1
        assert result[0]["type"] == "text"
        assert "Client information for 'test-host'" in result[0]["text"]
        assert "C.1234567890" in result[0]["text"]
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

        # Mock arguments
        from velociraptor_mcp_server.server import GetAgentInfoArgs

        args = GetAgentInfoArgs(hostname="nonexistent-host")

        # Execute the tool
        result = await get_agent_info_tool(args)

        # Verify result
        assert len(result) == 1
        assert result[0]["type"] == "text"
        assert "No client found with hostname: nonexistent-host" in result[0]["text"]
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

        # Mock arguments
        from velociraptor_mcp_server.server import RunVQLQueryArgs

        args = RunVQLQueryArgs(vql="SELECT * FROM clients() LIMIT 10")

        # Execute the tool
        result = await run_vql_query_tool(args)

        # Verify result
        assert len(result) == 1
        assert result[0]["type"] == "text"
        result_data = json.loads(result[0]["text"])
        assert len(result_data) == 2
        assert result_data[0]["client_id"] == "C.1234567890"
        mock_client.run_vql_query.assert_called_once_with("SELECT * FROM clients() LIMIT 10")


class TestCreateServer:
    """Test create_server factory function."""

    def test_create_server_with_config(self, config):
        """Test create_server with provided config."""
        server = create_server(config)

        assert isinstance(server, VelociraptorMCPServer)
        assert server.config == config

    @patch("velociraptor_mcp_server.server.Config.from_env")
    def test_create_server_without_config(self, mock_from_env, config):
        """Test create_server without config (uses env)."""
        mock_from_env.return_value = config

        server = create_server()

        assert isinstance(server, VelociraptorMCPServer)
        mock_from_env.assert_called_once()
