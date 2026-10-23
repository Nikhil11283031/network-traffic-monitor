# Network Traffic Monitor - container image
# Build:  docker build -t network-traffic-monitor .
# Run:    docker compose up        (then open http://127.0.0.1:5050)
FROM python:3.12-slim

# libpcap lets scapy capture live traffic; reading .pcap files does not need it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an ordinary user, not root (live capture needs extra rights - see README).
RUN useradd --create-home --uid 1000 netmon && chown -R netmon /app
USER netmon

EXPOSE 5050
ENTRYPOINT ["python", "-m", "netmon"]
# Listen on all interfaces inside the container so the published port works.
CMD ["pcap", "samples/demo.pcap", "--speed", "5", "--host", "0.0.0.0"]
