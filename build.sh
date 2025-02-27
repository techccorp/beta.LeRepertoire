#!/bin/bash
# build.sh - Build script for Render deployment of a Python-Flask app with Tailwind CSS

# Exit immediately if any command fails.
set -e

echo "Starting build process for Render deployment..."

# 1. Install Python dependencies.
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# 2. Install Node dependencies.
# If a package.json exists, use it; otherwise, install Tailwind CSS globally.
if [ -f package.json ]; then
  echo "Found package.json. Installing Node dependencies..."
  npm install
else
  echo "No package.json found. Installing Tailwind CSS globally..."
  npm install -g tailwindcss
fi

# 3. Build Tailwind CSS assets.
# Input: styles.css, Output: output.css (adjust paths as needed).
echo "Compiling Tailwind CSS..."
npx tailwindcss -i ./static/css/style.css -o ./static/css/output.css --minify

# 4. Optional: Run database migrations if using a migration tool (e.g., Flask-Migrate).
# Uncomment the lines below if applicable.
#
# echo "Running database migrations..."
# flask db upgrade

echo "Build process completed successfully."
