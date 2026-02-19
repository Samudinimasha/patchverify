#!/bin/bash
# PatchVerify Installation Script

set -e

echo "======================================"
echo "  PatchVerify Installation"
echo "======================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    echo "Please install Python 3 and try again."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✓ Python $PYTHON_VERSION detected"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install requirements
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt > /dev/null 2>&1
fi

# Install the package
echo "Installing PatchVerify..."
pip install -e . > /dev/null 2>&1

echo ""
echo "======================================"
echo "  Installation Complete!"
echo "======================================"
echo ""
echo "To use PatchVerify, run:"
echo "  source .venv/bin/activate"
echo "  patchverify --help"
echo ""
echo "Or create an alias in your ~/.zshrc or ~/.bashrc:"
echo "  alias patchverify='source /Users/nimashafernando/Downloads/patchnew/.venv/bin/activate && patchverify'"
echo ""
