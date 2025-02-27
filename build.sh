#!/bin/bash
# build.sh - Production-ready build script for Render deployment

# Exit immediately on any error and show each command
set -ex

echo "Starting production build process..."

# 1. Install Node.js using NVM (LTS version)
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] || curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm install --lts
nvm use --lts

# 2. Install Python dependencies with pip
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt --no-cache-dir

# 3. Node.js dependency management
if [ -f package.json ]; then
  echo "Installing Node dependencies from package.json..."
  npm install --production
else
  echo "Initializing Node project with Tailwind CSS..."
  npm init -y
  npm install tailwindcss postcss autoprefixer --save-prod
  npx tailwindcss init -p
fi

# 4. Ensure Tailwind configuration exists
if [ ! -f tailwind.config.js ]; then
  echo "Generating Tailwind config..."
  cat <<EOF > tailwind.config.js
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/src/**/*.js",
    "./app.py",
    "./routes/**/*.py"
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
EOF
fi

# 5. Build Tailwind CSS assets
echo "Compiling production Tailwind CSS..."
npx tailwindcss -i ./static/css/style.css -o ./static/css/output.css --minify

# 6. Validate critical assets
required_files=(
  "app.py"
  "requirements.txt"
  "static/css/output.css"
)
for file in "${required_files[@]}"; do
  if [ ! -f "$file" ]; then
    echo "ERROR: Missing critical file: $file"
    exit 1
  fi
done

echo "Production build completed successfully."
