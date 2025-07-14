#!/usr/bin/env python3
"""
Test script for Velociraptor MCP Server authentication.

This script demonstrates how to use the VelociraptorClient to authenticate
and perform basic operations with a Velociraptor server.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the package to Python path for testing
sys.path.insert(0, str(Path(__file__).parent / "velociraptor_mcp_server"))

from velociraptor_mcp_server.client import VelociraptorClient
from velociraptor_mcp_server.config import VelociraptorConfig
from velociraptor_mcp_server.exceptions import VelociraptorAuthenticationError, VelociraptorAPIError


async def test_authentication():
    """Test the authentication functionality."""
    print("🧪 Testing Velociraptor MCP Server Authentication")
    print("=" * 50)

    # Load configuration from environment
    try:
        config = VelociraptorConfig.from_env()
        print(f" API Key/Config: {config.api_key}")
        print(f"🔒 SSL Verify: {config.ssl_verify}")
        print(f"⏱️  Timeout: {config.timeout}s")
        print()

        if not config.api_key:
            print("❌ Error: VELOCIRAPTOR_API_KEY not set!")
            print("Please set the environment variable to point to your api.config.yaml file")
            return False

        if not os.path.exists(config.api_key):
            print(f"❌ Error: Config file not found: {config.api_key}")
            print("Please ensure the path points to a valid api.config.yaml file")
            return False

    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

    # Test authentication
    try:
        print("🔐 Attempting authentication...")
        client = VelociraptorClient(config)

        result = await client.authenticate()
        print("✅ Authentication successful!")
        print(f"📊 Connection details:")
        for key, value in result.items():
            if key == "test_query_result":
                print(f"   {key}: {value}")
            else:
                print(f"   {key}: {value}")
        print()

        # Test a simple VQL query
        print("🔍 Testing VQL query...")
        test_result = client.run_vql_query("SELECT 'Hello from Velociraptor!' as message")
        print(f"✅ VQL query successful: {test_result}")
        print()

        # Test client listing (basic functionality)
        print("👥 Testing client listing...")
        clients_result = client.run_vql_query("SELECT client_id, os_info.hostname as hostname FROM clients() LIMIT 5")
        print(f"✅ Found {len(clients_result)} clients")
        for client_info in clients_result:
            print(f"   Client ID: {client_info.get('client_id', 'N/A')}, Hostname: {client_info.get('hostname', 'N/A')}")
        print()

        # Cleanup
        client.close()
        print("✅ All tests passed! Velociraptor integration is working correctly.")
        return True

    except VelociraptorAuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        return False
    except VelociraptorAPIError as e:
        print(f"❌ API error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def main():
    """Main entry point."""
    print("Velociraptor MCP Server - Authentication Test")
    print("This test requires:")
    print("1. A running Velociraptor server")
    print("2. A valid api.config.yaml file")
    print("3. VELOCIRAPTOR_API_KEY environment variable set to the config file path")
    print()

    # Check for required environment variables
    if not os.getenv("VELOCIRAPTOR_API_KEY"):
        print("Please set the following environment variable:")
        print("export VELOCIRAPTOR_API_KEY=/path/to/api.config.yaml")
        return 1

    # Run the test
    try:
        success = asyncio.run(test_authentication())
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n❌ Test interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Test failed with unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
