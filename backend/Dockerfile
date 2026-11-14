# Orion.ai backend — FastAPI app + Celery worker + the 19 scanning tool wrappers.
# Same image serves both the `backend` and `celery_worker` services in docker-compose.yml.
#
# Stage 1: compile the Go-based scanning tools (ProjectDiscovery's httpx/katana/
# nuclei/subfinder, plus dalfox, ffuf, gau) so the final image doesn't need a
# Go toolchain at runtime.
FROM golang:1.22-alpine AS gobuild
RUN apk add --no-cache git
ENV GOBIN=/go/bin
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/hahwul/dalfox/v2@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest

# Stage 2: runtime image.
FROM python:3.11-slim
WORKDIR /backend

# System-level scanning tools (nmap, whatweb) + build deps for Python
# packages that compile native extensions (bcrypt, etc).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap whatweb git curl ca-certificates gcc g++ make libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Compiled Go tools from stage 1.
COPY --from=gobuild /go/bin/* /usr/local/bin/

# Python dependencies, including the Python-CLI scanning tools (sqlmap, arjun).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir sqlmap arjun

# Refresh nuclei's vulnerability templates at build time so the first real
# scan doesn't pay that download cost.
RUN nuclei -update-templates -silent || true

COPY . .

EXPOSE 8000
CMD ["uvicorn", "orion.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
