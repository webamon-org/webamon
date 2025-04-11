FROM python:3.11 as build

RUN curl -Lo "/tmp/chromedriver-linux64.zip" "https://storage.googleapis.com/chrome-for-testing-public/123.0.6312.86/linux64/chromedriver-linux64.zip" && \
    curl -Lo "/tmp/chrome-linux64.zip" "https://storage.googleapis.com/chrome-for-testing-public/123.0.6312.86/linux64/chrome-linux64.zip" && \
    unzip /tmp/chromedriver-linux64.zip -d /opt/ && \
    unzip /tmp/chrome-linux64.zip -d /opt/

FROM python:3.11

WORKDIR /app

# Install required dependencies
RUN apt-get update && \
    apt-get install -y wget unzip curl fonts-liberation libasound2 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 libcups2 libdbus-1-3 libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 libxcomposite1 libxdamage1 libxfixes3 libxkbcommon0 libxrandr2 xdg-utils libu2f-udev

# Copy Chrome and Chromedriver from build stage
COPY --from=build /opt/chrome-linux64 /app/chrome
COPY --from=build /opt/chromedriver-linux64 /app/

# Copy application files
COPY . /app


ARG GEOLITE_LICENSE_KEY
ARG GEOLITE_ACCOUNT_ID
ARG ELASTIC_USERNAME
ARG ELASTIC_PASSWORD
ARG ELASTIC_BASE


ENV PATH="/app:$PATH"

# General Configuration
ENV SOURCE="url"
ENV SCAN_TYPE=""
ENV SCAN_TIMEOUT=20
ENV THREADS=1
ENV USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.3"
ENV URL="https://webamon.com"
ENV TAG=""
ENV SET_COOKIES='{}'
ENV LOG_LEVEL="INFO"
ENV COMPARE_PREVIOUS="False"
ENV SKIP_IF_EXISTS="False"
ENV QUEUE_WORKER="True"
ENV HASH_TYPES=""
ENV WEBAMON_APIKEY=''

# Resource Saving Configuration
ENV SAVE_ELASTIC="True"
ENV SAVE_IMAGES="False"
ENV SAVE_CSS="False"
ENV SAVE_DOM="True"
ENV SAVE_SCREENSHOT="True"
ENV SAVE_RESOURCES="True"

# AWS Configuration TODO
ENV AWS_SAVE="False"
ENV AWS_KEY=""
ENV AWS_RESOURCE_BUCKET=""
ENV AWS_DOM_BUCKET=""
ENV AWS_SCREENSHOT_BUCKET=""

# ElasticSearch Configuration
ENV ELASTIC_BASE=${ELASTIC_BASE}
ENV ELASTIC_USERNAME=${ELASTIC_USERNAME}
ENV ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
ENV ELASTIC_QUERY=""
ENV ELASTIC_QUERY_INDEX=""
ENV ELASTIC_SIZE=100

# Monitoring and Analysis
ENV THREAT_AI="False"
ENV THREAT_AI_ENDPOINT="http://copilot:9090/chat"
ENV MONITOR="False"

# MaxMind GeoIP Credentials
ENV GEOLITE_LICENSE_KEY=${GEOLITE_LICENSE_KEY}
ENV GEOLITE_ACCOUNT_ID=${GEOLITE_ACCOUNT_ID}

# DNS and WHOIS
ENV WHOIS="False"
ENV DNS="True"
ENV RDNS="False"
ENV CHECK_DANGLING="False"
ENV CHECK_PORTS=""

# Download and extract GeoLite2 databases using basic auth
RUN mkdir -p /app/geoIP && cd /app/geoIP && \
    curl -L -u ${GEOLITE_ACCOUNT_ID}:${GEOLITE_LICENSE_KEY} -o GeoLite2-ASN.tar.gz https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz && \
    curl -L -u ${GEOLITE_ACCOUNT_ID}:${GEOLITE_LICENSE_KEY} -o GeoLite2-Country.tar.gz https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz && \
    tar -xzf GeoLite2-ASN.tar.gz && \
    tar -xzf GeoLite2-Country.tar.gz && \
    find . -name "*.mmdb" -exec mv {} /app/geoIP/ \;

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create volume for scan inputs/outputs
VOLUME ["/app/data"]

EXPOSE 5000

CMD python main.py > /dev/stdout
