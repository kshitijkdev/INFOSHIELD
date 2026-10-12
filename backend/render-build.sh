#!/usr/bin/env bash
# exit on error
set -o errexit

echo "==> InfoShield Render Build Script"
echo "==> Python version: $(python --version)"

# Install pip requirements
pip install --upgrade pip
pip install -r requirements.txt

# Check if Tesseract is installed on the system
if command -v tesseract &> /dev/null; then
    echo "==> Tesseract binary found at: $(which tesseract)"
    tesseract --version
else
    echo "==> Note: For native Render Python runtimes without root, we strongly recommend"
    echo "==> deploying via the provided Dockerfile which installs Tesseract automatically."
fi

echo "==> Build complete."
