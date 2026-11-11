# Webamon Sandbox - scanner image.
#
# The Playwright base image ships Chromium plus the system libraries it needs.
# Its tag MUST match the playwright pin in requirements.txt: each Playwright
# release drives one specific Chromium build, and a mismatch fails at launch
# with "Executable doesn't exist".
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY sandbox /app/sandbox
COPY technology_patterns.txt /app/technology_patterns.txt

# Runtime defaults. Every setting can be overridden with an environment
# variable of the same name (see sandbox/config.py and docker-compose.yml).
ENV queue_worker=True \
    api_port=5000 \
    threads=4 \
    scan_timeout=30 \
    browser_pool_size=2 \
    browser_max_scans=200 \
    resources=scripts \
    save_elastic=True \
    save_dom=True \
    save_resources=True \
    save_screenshot=False \
    favicon_hashing=True \
    block_private_networks=True \
    dns=ALL \
    log_level=INFO

# MaxMind GeoLite2 databases are mounted at run time, never baked into the
# image. Without them scans still complete, just without country/ASN data.
ENV geoip_asn_path=/app/geoIP/GeoLite2-ASN.mmdb \
    geoip_country_path=/app/geoIP/GeoLite2-Country.mmdb

# Run as the non-root user the Playwright image provides.
USER pwuser

VOLUME ["/app/data", "/app/geoIP"]
EXPOSE 5000

CMD ["python", "-m", "sandbox"]
