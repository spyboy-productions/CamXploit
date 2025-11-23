#!/bin/bash

# Check if uv is installed
if ! command -v uv &> /dev/null
then
    echo "uv could not be found, installing it now..."
    pip install uv
fi

echo "Creating virtual environment using uv..."
uv venv

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing dependencies using uv..."
uv pip install -r requirements.txt
uv pip install Flask

echo "Setup complete. To run the application, execute the following command:"
echo "source .venv/bin/activate && python3 server.py"
