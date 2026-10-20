# Shared runtime image for lab Python services (agents, MCP servers, seed jobs, Autopilot).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd -r -u 10001 -m aplab && useradd -r -u 10002 -M apdeployer && groupadd -g 10010 apdb \
    && usermod -aG apdb aplab && usermod -aG apdb apdeployer \
    && apt-get update -q && apt-get install -y -q --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
COPY deploy/common/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
WORKDIR /opt/aplab
COPY app/aplab ./aplab
COPY app/services ./services
COPY app/autopilot ./autopilot
COPY packages/vendor/as3-schema-3.56.0-10.json /opt/aplab/packages/vendor/as3-schema-3.56.0-10.json
USER aplab
