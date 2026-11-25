
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo
echo "========================================"
echo "          Guardian Installation"
echo "========================================"
echo
echo "Before proceeding, ensure:"
echo "  - Docker is installed"
echo "  - Docker Desktop / Docker Engine is running"
echo "  - Docker Compose is available"
echo
echo "Guardian will run locally inside Docker."
echo
echo "What to expect:"
echo "  - Web UI hosted on this computer"
echo "  - Default Web UI port: 8080"
echo "  - Optional SSH terminal access"
echo "  - Default SSH port: 2222"
echo "  - SSH is NOT required to use Guardian"
echo
echo "Ports 8080 and 2222 are defaults."
echo "If a port is occupied, you can choose another."
echo
echo "The Docker image (~2.4 GB) will be built"
echo "during installation. This may take some time."
echo
echo "========================================"
read -r -p "Continue with installation? [Y/n]: " CONTINUE
CONTINUE="${CONTINUE:-Y}"

if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo
echo "Checking prerequisites..."
echo

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is not installed."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running or accessible."
    echo "Start Docker and try again."
    exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose plugin is unavailable."
    echo "Install Docker Compose and try again."
    exit 1
fi

echo "Docker:         OK"
echo "Docker Engine:  OK"
echo "Docker Compose: OK"

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

echo
echo "----------------------------------------"
echo "Web UI Configuration"
echo "----------------------------------------"

GUARDIAN_PORT="$(read_port 'Guardian Web UI port' 8080)"

echo
echo "----------------------------------------"
echo "Optional SSH Configuration"
echo "----------------------------------------"
echo
echo "SSH provides terminal access to the container."
echo "The Web UI works without SSH."
echo

read -r -p "Enable SSH terminal access? [y/N]: " ENABLE_SSH
ENABLE_SSH="${ENABLE_SSH:-N}"

GUARDIAN_SSH_ENABLED=0
GUARDIAN_SSH_PORT=2222

COMPOSE_FILES=(-f compose.yaml)

if [[ "$ENABLE_SSH" =~ ^[Yy]$ ]]; then
    GUARDIAN_SSH_ENABLED=1

    GUARDIAN_SSH_PORT="$(read_port 'Guardian SSH port' 2222)"

    if [[ "$GUARDIAN_PORT" == "$GUARDIAN_SSH_PORT" ]]; then
        echo "ERROR: Web UI and SSH cannot use the same host port."
        exit 1
    fi

    echo
    echo "----------------------------------------"
    echo "SSH Password Configuration"
    echo "----------------------------------------"
    echo
    echo "Choose a password for the guardian SSH user."
    echo "The password must not contain a colon (:)."
    echo

    while true; do
        read -r -s -p "Choose SSH password: " PASSWORD
        echo

        if [[ -z "$PASSWORD" ]]; then
            echo "Password cannot be empty."
            continue
        fi

        if [[ "$PASSWORD" == *:* ]]; then
            echo "Password cannot contain a colon (:)."
            continue
        fi

        read -r -s -p "Confirm SSH password: " PASSWORD_CONFIRM
        echo

        if [[ "$PASSWORD" == "$PASSWORD_CONFIRM" ]]; then
            break
        fi

        echo "Passwords do not match. Try again."
    done

    mkdir -p secrets
    chmod 700 secrets

    umask 077
    printf '%s' "$PASSWORD" > secrets/guardian_ssh_password

    unset PASSWORD PASSWORD_CONFIRM

    chmod 600 secrets/guardian_ssh_password

    cat > compose.ssh.yaml <<'EOF'
services:
  guardian:
    ports:
      - "127.0.0.1:${GUARDIAN_SSH_PORT:-2222}:22"
    secrets:
      - guardian_ssh_password

secrets:
  guardian_ssh_password:
    file: ./secrets/guardian_ssh_password
EOF

    COMPOSE_FILES+=(-f compose.ssh.yaml)

else
    echo
    echo "SSH disabled."
    echo "Guardian will be accessible through the Web UI only."

    rm -f compose.ssh.yaml
    rm -f secrets/guardian_ssh_password

    if [[ -d secrets ]] && [[ -z "$(ls -A secrets)" ]]; then
        rmdir secrets
    fi
fi

cat > .env <<EOF
GUARDIAN_PORT=$GUARDIAN_PORT
GUARDIAN_SSH_PORT=$GUARDIAN_SSH_PORT
GUARDIAN_SSH_ENABLED=$GUARDIAN_SSH_ENABLED
EOF

echo
echo "========================================"
echo "       Starting Guardian Installation"
echo "========================================"
echo
echo "Web UI port: $GUARDIAN_PORT"

if (( GUARDIAN_SSH_ENABLED == 1 )); then
    echo "SSH port:    $GUARDIAN_SSH_PORT"
else
    echo "SSH:         Disabled"
fi

echo
echo "Building and starting Guardian..."
echo "This may take several minutes."
echo

if ! docker compose "${COMPOSE_FILES[@]}" up -d --build; then
    echo
    echo "========================================"
    echo "Guardian installation failed."
    echo "========================================"
    echo
    echo "If the failure was caused by a port conflict:"
    echo
    echo "  1. Edit deploy/.env"
    echo "  2. Change GUARDIAN_PORT or GUARDIAN_SSH_PORT"
    echo "  3. Re-run setup.sh"
    echo
    echo "Alternatively, from the deploy directory,"
    echo "run Docker Compose using the same configuration"
    echo "files to recreate the container."
    echo
    exit 1
fi

echo
echo "========================================"
echo "     Guardian Installation Complete"
echo "========================================"
echo
echo "Host computer: Local"
echo
echo "Web UI:"
echo "  http://localhost:$GUARDIAN_PORT"
echo

if (( GUARDIAN_SSH_ENABLED == 1 )); then
    echo "SSH:"
    echo "  Username: guardian"
    echo "  Host:     localhost"
    echo "  Port:     $GUARDIAN_SSH_PORT"
    echo
    echo "Connect using:"
    echo "  ssh guardian@localhost -p $GUARDIAN_SSH_PORT"
    echo
    echo "SSH is optional; Guardian Web UI works independently."
fi

echo "----------------------------------------"
echo "If you need to change ports later:"
echo
echo "  1. Edit deploy/.env"
echo "  2. Change GUARDIAN_PORT or GUARDIAN_SSH_PORT"
echo "  3. Recreate Guardian using the same Compose files"
echo
echo "No image rebuild is required for port changes."
echo "----------------------------------------"
echo

