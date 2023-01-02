#!/bin/bash
set -e

# Start from a clean environment
rm -rf venv/

# Basic python3 virtual environment
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt

