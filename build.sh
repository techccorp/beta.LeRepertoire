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

# 5. Log environment variables (optional, for debugging purposes).
echo "Using the following environment variables:"
echo "GOOGLE_API_KEY: ${GOOGLE_API_KEY:-not set}"
echo "GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID:-not set}"
echo "GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET:-not set}"
echo "GOOGLE_PROJECT_ID: ${GOOGLE_PROJECT_ID:-not set}"
echo "GOOGLE_REDIRECT_URI: ${GOOGLE_REDIRECT_URI:-not set}"
echo "JWT_SECRET_KEY: ${JWT_SECRET_KEY:-not set}"
echo "MONGO_DBNAME: ${MONGO_DBNAME:-not set}"
echo "MONGO_URI: ${MONGO_URI:-not set}"
echo "SECRET_KEY: ${SECRET_KEY:-not set}"

echo "Build process completed successfully."
