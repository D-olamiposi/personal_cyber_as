# Packages are installed at image-build time, never by untrusted code cells.
FROM python:3.12-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl dnsutils jq nmap \
    && rm -rf /var/lib/apt/lists/*
COPY python-packages.txt /opt/python-packages.txt
RUN python -m pip install --no-cache-dir -r /opt/python-packages.txt
USER 65534:65534
WORKDIR /tmp
