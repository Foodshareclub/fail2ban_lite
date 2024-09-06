FROM python:3.9-slim

RUN apt-get update && apt-get install -y iptables systemd && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY fail2ban_lite.py .

CMD ["python", "fail2ban_lite.py"]
