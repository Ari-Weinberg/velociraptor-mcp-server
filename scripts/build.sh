#!/bin/bash
# Build script for velociraptor-mcp-server

set -e

echo "🚀 Building velociraptor-mcp-server package..."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build/
rm -rf dist/
rm -rf *.egg-info/

# Install build dependencies
echo "📦 Installing build dependencies..."
pip install --upgrade pip
pip install build twine wheel

# Build the package
echo "🔨 Building the package..."
python -m build

# Check the package
echo "🔍 Checking package integrity..."
twine check dist/*

# List built files
echo "📄 Built files:"
ls -la dist/

echo "✅ Package built successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Test the package: pip install dist/velociraptor_mcp_server-*.whl"
echo "2. Create a GitHub release with the built artifacts"
echo "3. Install from GitHub: pip install git+https://github.com/yourusername/velociraptor-mcp-server.git"
