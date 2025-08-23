#!/bin/bash

#!/bin/bash
# filepath: /Users/jbarwick/Development/simple-cloud-kit/sck-core-api/start.sh

# Default values
HOSTNAME="localhost"
PORT=8090
UV_LOG_LEVEL="debug"
NO_RELOAD=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --no-reload)
            NO_RELOAD=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --hostname HOST    Server hostname (default: localhost)"
            echo "  --port PORT        Server port (default: 8090)"
            echo "  --log-level LEVEL  Log level (default: debug)"
            echo "  --no-reload        Disable auto-reload"
            echo "  -h, --help         Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

set -e  # Exit on error

# Set environment variables
export HOST="$HOSTNAME"
export PORT="$PORT"
export LOG_LEVEL=$(echo "$UV_LOG_LEVEL" | tr '[:lower:]' '[:upper:]')  # Convert to uppercase
export VOLUME="$HOME/core"
export LOG_PATH="$HOME/core/logs"
export CLIENT="test-client"

# Ensure directories exist
for dir in "$VOLUME" "$LOG_PATH"; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        echo -e "\033[32mCreated directory: $dir\033[0m"
    fi
done

# Build uvicorn command arguments
uvicorn_args=(
    "core_api.api.fast_api:get_app"
    "--factory"
    "--host" "$HOSTNAME"
    "--port" "$PORT"
    "--log-level" "$UV_LOG_LEVEL"
    "--proxy-headers"
    "--forwarded-allow-ips=*"
    "--access-log"
)

if [[ "$NO_RELOAD" != true ]]; then
    uvicorn_args+=("--reload" "--reload-dir" "./core_api")
fi

# If a .env file exists, pass it to uvicorn
if [[ -f "$ENV_FILE" ]]; then
    uvicorn_args+=("--env-file" "$ENV_FILE")
    echo -e "\033[33mUsing env file: $ENV_FILE\033[0m"
else
    echo -e "\033[93mNo .env file found at: $ENV_FILE\033[0m"
fi

echo -e "\033[32mStarting FastAPI server...\033[0m"
echo -e "\033[33mConfiguration:\033[0m"
echo -e "\033[36m  Client: $CLIENT\033[0m"
echo -e "\033[36m  Host: $HOST\033[0m"
echo -e "\033[36m  Port: $PORT\033[0m"
echo -e "\033[36m  Log Level: $UV_LOG_LEVEL\033[0m"
echo -e "\033[36m  Volume: $VOLUME\033[0m"
echo -e "\033[36m  Log Path: $LOG_PATH\033[0m"
echo -e "\033[36m  Reload: $([[ "$NO_RELOAD" != true ]] && echo "true" || echo "false")\033[0m"

# Start the server
if ! uvicorn "${uvicorn_args[@]}"; then
    echo -e "\033[31mError starting server\033[0m" >&2
    exit 1
fi