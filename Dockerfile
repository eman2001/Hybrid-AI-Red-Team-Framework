FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git perl python3 curl nmap netcat-openbsd whois dnsutils bash \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports/json reports/pdf logs database data models scan_results

CMD ["python", "main.py"]
