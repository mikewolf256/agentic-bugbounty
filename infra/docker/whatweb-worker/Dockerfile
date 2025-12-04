# WhatWeb Worker - On-demand container for fingerprinting
FROM ruby:3.2-slim

LABEL maintainer="Agentic Bug Bounty"
LABEL description="WhatWeb worker for on-demand fingerprinting jobs"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install WhatWeb
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && chmod +x /opt/whatweb/whatweb

# Install AWS SDK and worker script dependencies
RUN pip3 install --no-cache-dir boto3 requests redis

# Copy worker scripts
COPY worker.py /app/worker.py
COPY worker-local.py /app/worker-local.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PATH="/opt/whatweb:${PATH}"

WORKDIR /app

# Health check marker
RUN touch /tmp/healthy

ENTRYPOINT ["/app/entrypoint.sh"]

