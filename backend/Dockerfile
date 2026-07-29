# OSscanner backend.
#
# IMPORTANT: this app's whole purpose is inspecting the HOST machine's real
# processes, network state, logs, users, and startup persistence. Run with
# plain `docker run -p 5000:5000 osscanner-backend` and every scanner sees
# only the container's own isolated view - a handful of container processes,
# no real connections, an empty /var/log, no real user accounts - which is
# fine for exercising the API but is not a real security scan. See the
# "Running the backend in Docker" section in the top-level README for the
# host-namespace/bind-mount flags needed for scanners to see the real host,
# and for the one scanner (permission_scanner) that can't be made to see the
# real host this way without extra code changes.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 0.0.0.0 is correct and intentional here (unlike the bare-metal default of
# 127.0.0.1) - Docker's own port publishing (`-p`) is the actual exposure
# control an operator opts into, and a container process bound to its own
# loopback wouldn't be reachable through published ports at all.
ENV FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    FLASK_DEBUG=0

EXPOSE 5000

CMD ["python3", "app.py"]
