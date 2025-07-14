"""
Tests for configuration management.
"""

import os
from unittest.mock import patch

import pytest

from velociraptor_mcp_server.config import Config, ServerConfig, VelociraptorConfig


class TestVelociraptorConfig:
    """Test Velociraptor configuration."""

    def test_init(self):
        """Test VelociraptorConfig initialization."""
        config = VelociraptorConfig(
            api_key="/path/to/api.config.yaml",
            ssl_verify=False,
            timeout=30,
        )

        assert config.api_key == "/path/to/api.config.yaml"
        assert config.ssl_verify is False
        assert config.timeout == 30

    def test_from_env(self):
        """Test VelociraptorConfig from environment variables."""
        env_vars = {
            "VELOCIRAPTOR_API_KEY": "/env/path/to/api.config.yaml",
            "VELOCIRAPTOR_SSL_VERIFY": "false",
            "VELOCIRAPTOR_TIMEOUT": "60",
        }

        with patch.dict(os.environ, env_vars):
            config = VelociraptorConfig.from_env()

            assert config.api_key == "/env/path/to/api.config.yaml"
            assert config.ssl_verify is False
            assert config.timeout == 60

    def test_validate_success(self):
        """Test successful validation."""
        config = VelociraptorConfig(api_key="/path/to/api.config.yaml")

        # Mock file existence
        with patch("os.path.exists", return_value=True):
            # Should not raise an exception
            config.validate()

    def test_validate_missing_api_key(self):
        """Test validation with missing API key."""
        config = VelociraptorConfig(api_key="")

        with pytest.raises(ValueError, match="Velociraptor API key/config path is required"):
            config.validate()


class TestServerConfig:
    """Test server configuration."""

    def test_init(self):
        """Test ServerConfig initialization."""
        config = ServerConfig(
            host="0.0.0.0",
            port=8080,
            log_level="DEBUG",
            disabled_tools=["AuthenticateTool"],
            disabled_categories=["dangerous"],
            read_only=True,
        )

        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.log_level == "DEBUG"
        assert config.disabled_tools == ["AuthenticateTool"]
        assert config.disabled_categories == ["dangerous"]
        assert config.read_only is True

    def test_from_env(self):
        """Test ServerConfig from environment variables."""
        env_vars = {
            "MCP_SERVER_HOST": "0.0.0.0",
            "MCP_SERVER_PORT": "8080",
            "LOG_LEVEL": "DEBUG",
            "VELOCIRAPTOR_DISABLED_TOOLS": "AuthenticateTool,GetAgentsTool",
            "VELOCIRAPTOR_DISABLED_CATEGORIES": "dangerous,write",
            "VELOCIRAPTOR_READ_ONLY": "true",
        }

        with patch.dict(os.environ, env_vars):
            config = ServerConfig.from_env()

            assert config.host == "0.0.0.0"
            assert config.port == 8080
            assert config.log_level == "DEBUG"
            assert config.disabled_tools == ["AuthenticateTool", "GetAgentsTool"]
            assert config.disabled_categories == ["dangerous", "write"]
            assert config.read_only is True


class TestConfig:
    """Test main configuration."""

    def test_init(self, velociraptor_config, server_config):
        """Test Config initialization."""
        config = Config(velociraptor=velociraptor_config, server=server_config)

        assert config.velociraptor == velociraptor_config
        assert config.server == server_config

    def test_validate_success(self, config):
        """Test successful validation."""
        # Mock file existence
        with patch("os.path.exists", return_value=True):
            # Should not raise an exception
            config.validate()

    def test_validate_invalid_velociraptor_config(self, server_config):
        """Test validation with invalid Velociraptor config."""
        invalid_velociraptor_config = VelociraptorConfig(
            api_key="",  # Invalid empty API key
        )

        config = Config(velociraptor=invalid_velociraptor_config, server=server_config)

        with pytest.raises(ValueError, match="Velociraptor API key/config path is required"):
            config.validate()
