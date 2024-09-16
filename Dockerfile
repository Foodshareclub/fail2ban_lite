FROM python:3.9-slim

WORKDIR /app

# Install iptables and other necessary tools
RUN apt-get update && apt-get install -y iptables curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

# Create necessary directories
RUN mkdir -p /var/log /app/logs /app/config

EXPOSE 8082

CMD ["python", "fail2ban_lite.py"]
