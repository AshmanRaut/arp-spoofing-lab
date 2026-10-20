FROM python:3.11-slim

# Install Docker CLI so we can also call `docker compose` via subprocess
# when the Python SDK doesn't expose the compose subcommand directly.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        gnupg \
        lsb-release \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py docker_control.py ./

# The host docker-compose.yml must mount /var/run/docker.sock into this
# container so the Python SDK can reach the host Docker daemon:
#   volumes:
#     - /var/run/docker.sock:/var/run/docker.sock
#
# It must also mount the project root so docker compose commands can find
# the docker-compose.yml:
#   volumes:
#     - ..:/workspace
# and set COMPOSE_PROJECT_DIR=/workspace (or pass --project-directory).

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
