#!/bin/bash
set -eu

SECRET_FILE="/run/secrets/guardian_ssh_password"

# Ensure the SSH password secret is available
if [ ! -s "$SECRET_FILE" ]; then
    echo "ERROR: SSH password secret is missing or empty."
    exit 1
fi

# Provision the guardian account password
GUARDIAN_PASSWORD="$(cat "$SECRET_FILE")"

if [ -z "$GUARDIAN_PASSWORD" ]; then
    echo "ERROR: SSH password cannot be empty."
    exit 1
fi

printf 'guardian:%s\n' "$GUARDIAN_PASSWORD" | chpasswd
unset GUARDIAN_PASSWORD

# Generate fresh SSH host keys for this container
mkdir -p /run/sshd
ssh-keygen -A

# Configure SSH access
cat > /etc/ssh/sshd_config.d/00-guardian.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AllowUsers guardian
EOF

# Validate SSH configuration before starting services
sshd -t

echo "Guardian container initialization complete."

# Start Supervisor as the container's main process
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
