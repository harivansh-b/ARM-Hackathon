
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install runtime and service dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    openssh-server \
    supervisor \
    ca-certificates \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN useradd --create-home --shell /bin/bash guardian

# Application location
WORKDIR /opt/guardian

# Copy Guardian application and required runtime assets
COPY guardian_sms_pipeline.sh ./
COPY guardian_network_pipeline.sh ./
COPY guardian ./guardian
COPY guardian_web ./guardian_web
COPY person-a ./person-a
COPY person-b ./person-b
COPY person-c ./person-c
COPY models ./models
COPY runtime ./runtime
COPY deploy/entrypoint.sh /usr/local/bin/guardian-entrypoint
COPY deploy/supervisord.conf /etc/supervisor/supervisord.conf

# Prepare SSH and application directories
RUN mkdir -p /run/sshd /var/log/supervisor \
    /opt/guardian/person-b/reports \
    && chmod +x ./guardian ./runtime/executorch/llama_main \
    && chown -R root:root /opt/guardian \
    && chown -R guardian:guardian /opt/guardian/person-b/reports

EXPOSE 22 8080
RUN chmod +x /usr/local/bin/guardian-entrypoint

ENTRYPOINT ["/usr/local/bin/guardian-entrypoint"]
