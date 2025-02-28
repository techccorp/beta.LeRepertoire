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

# 5. Ensure MongoDB indexes are set up correctly
echo "Setting up MongoDB indexes..."
# We'll make this part robust to failures so it doesn't stop the deployment
python -c "try:
    from app import app
    from db.indexes_setup import init_indexes
    with app.app_context():
        init_indexes(app)
    print('MongoDB indexes setup complete.')
except Exception as e:
    print(f'Warning: Could not initialize MongoDB indexes: {str(e)}')
    print('Continuing deployment anyway...')
" || echo "MongoDB index setup failed, but continuing deployment."

echo "Build process completed successfully."
