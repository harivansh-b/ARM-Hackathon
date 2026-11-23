
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================"
echo "       Guardian Setup"
echo "================================"

# Check Docker availability
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is not installed."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running or accessible."
    exit 1
fi

# Read and validate a host port
read_port() {
    local prompt="$1"
    local default="$2"
    local port

    while true; do
        read -r -p "$prompt [$default]: " port
        port="${port:-$default}"

        if [[ "$port" =~ ^[0-9]+$ ]] &&
           (( port >= 1024 && port <= 65535 )); then
            printf '%s' "$port"
            return
        fi

        echo "Enter a port between 1024 and 65535." >&2
    done
}

# Collect organiser configuration
GUARDIAN_PORT="$(read_port 'Guardian webapp port (default: 8080)' 8080)"
GUARDIAN_SSH_PORT="$(read_port 'Guardian SSH port (default: 2222)' 2222)"

# Persist organiser port configuration for Docker Compose
cat > .env <<EOF
GUARDIAN_PORT=$GUARDIAN_PORT
GUARDIAN_SSH_PORT=$GUARDIAN_SSH_PORT
EOF

# Collect SSH password without displaying it
while true; do
    read -r -s -p "Choose SSH password (minimum 12 characters): " PASSWORD
    echo

    if (( ${#PASSWORD} < 12 )) || [[ "$PASSWORD" == *:* ]]; then
        echo "Password must have at least 12 characters and no colon."
        continue
    fi

    read -r -s -p "Confirm SSH password: " PASSWORD_CONFIRM
    echo

    if [[ "$PASSWORD" == "$PASSWORD_CONFIRM" ]]; then
        break
    fi

    echo "Passwords do not match. Try again."
done

# Store the password in a restricted host-side secret file
mkdir -p secrets
chmod 700 secrets
umask 077
printf '%s' "$PASSWORD" > secrets/guardian_ssh_password
unset PASSWORD PASSWORD_CONFIRM
chmod 600 secrets/guardian_ssh_password

# Build and launch Guardian in the background
export GUARDIAN_PORT GUARDIAN_SSH_PORT

echo
echo "Building and starting Guardian..."

docker compose -f compose.yaml up -d --build

echo
echo "================================"
echo "Guardian installation complete."
echo "Webapp: http://localhost:$GUARDIAN_PORT"
echo "SSH:    localhost:$GUARDIAN_SSH_PORT"
echo "================================"
