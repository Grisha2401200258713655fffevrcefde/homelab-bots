FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Nuclei binary (ProjectDiscovery)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d 'v')_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && apt-get purge -y unzip && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

CMD ["python", "bot.py"]
