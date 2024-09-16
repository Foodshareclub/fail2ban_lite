FROM python:3.9-slim

WORKDIR /app

# Install iptables
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["python", "fail2ban_lite.py"]
