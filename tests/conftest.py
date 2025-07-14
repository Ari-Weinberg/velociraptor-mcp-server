"""
Test configuration for pytest.
"""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from velociraptor_mcp_server.client import VelociraptorClient
from velociraptor_mcp_server.config import Config, ServerConfig, VelociraptorConfig


@pytest.fixture
def velociraptor_config():
    """Create a test Velociraptor configuration."""
    return VelociraptorConfig(
        api_key="/path/to/test/api.config.yaml",
        ssl_verify=False,
        timeout=10,
    )


@pytest.fixture
def server_config():
    """Create a test server configuration."""
    return ServerConfig(
        host="127.0.0.1",
        port=8000,
        log_level="INFO",
        disabled_tools=[],
        disabled_categories=[],
        read_only=False,
    )


@pytest.fixture
def config(velociraptor_config, server_config):
    """Create a test configuration."""
    return Config(velociraptor=velociraptor_config, server=server_config)


@pytest.fixture
def mock_grpc_client():
    """Create a mock gRPC client."""
    client = Mock()
    client.Query = Mock()
    return client


@pytest.fixture
def velociraptor_client(velociraptor_config, mock_grpc_client):
    """Create a test Velociraptor client."""
    client = VelociraptorClient(velociraptor_config)
    client.stub = mock_grpc_client
    return client


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
