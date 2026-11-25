#!/bin/bash
set -eu

if [[ "${GUARDIAN_SSH_ENABLED:-0}" == "1" ]]; then
    SECRET_FILE="/run/secrets/guardian_ssh_password"

    if [ ! -s "$SECRET_FILE" ]; then
        echo "ERROR: SSH is enabled, but its password secret is missing or empty."
        exit 1
    fi

    GUARDIAN_PASSWORD="$(cat "$SECRET_FILE")"

    if [ -z "$GUARDIAN_PASSWORD" ]; then
        echo "ERROR: SSH password cannot be empty."
        exit 1
    fi

    printf 'guardian:%s\n' "$GUARDIAN_PASSWORD" | chpasswd
    unset GUARDIAN_PASSWORD

    mkdir -p /run/sshd /var/lib/guardian-ssh

    for key_type in rsa ecdsa ed25519; do
        key_file="/var/lib/guardian-ssh/ssh_host_${key_type}_key"

        if [ ! -f "$key_file" ]; then
            ssh-keygen -t "$key_type" -f "$key_file" -N ""
        fi
    done

    chmod 600 /var/lib/guardian-ssh/ssh_host_*_key
    cat > /etc/ssh/sshd_config.d/00-guardian.conf <<'SSHCONF'
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AllowUsers guardian
SSHCONF

    sshd -t

    cat > /etc/supervisor/conf.d/sshd.conf <<'SUPERVISORSSH'
[program:sshd]
command=/usr/sbin/sshd -D -e
autostart=true
autorestart=true
startsecs=2
priority=10
user=root
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/2
stderr_logfile_maxbytes=0
SUPERVISORSSH

    echo "SSH initialization complete."

else
    rm -f /etc/supervisor/conf.d/sshd.conf
    echo "SSH disabled; starting Guardian Web UI only."
fi

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
