#!/bin/bash

# if pylint is not installed, install it
if ! command -v pylint &> /dev/null
then
    echo "pylint could not be found, installing..."
    pip install pylint
fi

# if the environment is not active, activate it
echo "Activating virtual environment..."
source ./.venv/bin/activate

# Run pylint
pylint core_api