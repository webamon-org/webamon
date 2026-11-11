#!/bin/bash
# One-time OpenSearch / Dashboards setup for the Webamon Sandbox stack.
#
# The scanner installs its own index templates (scans-*, resources-*,
# domains/servers) on startup, so this script only:
#   1. adds the screenshots-* template (screenshots are stored as binary), and
#   2. creates the OpenSearch Dashboards index patterns.
# Safe to run more than once.
set -e

OPENSEARCH_URL="${OPENSEARCH_URL:-https://webamon-node1:9200}"
DASHBOARDS_URL="${DASHBOARDS_URL:-http://webamon-dashboards:5601}"
AUTH="${OPENSEARCH_USERNAME:-admin}:${OPENSEARCH_PASSWORD:?OPENSEARCH_PASSWORD is not set}"

echo "Waiting for OpenSearch..."
until curl -s --fail -k -u "$AUTH" "${OPENSEARCH_URL}/_cluster/health" > /dev/null; do
  sleep 5
done

echo "Installing the screenshots index template..."
curl -s --fail -k -u "$AUTH" -X PUT "${OPENSEARCH_URL}/_index_template/webamon-screenshots" \
  -H "Content-Type: application/json" -d '{
  "index_patterns": ["screenshots-*"],
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "properties": {
        "report_id":      { "type": "keyword" },
        "screenshot":     { "type": "binary" },
        "page_title":     { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } } },
        "domain_name":    { "type": "keyword" },
        "submission_url": { "type": "keyword" },
        "submission_utc": { "type": "date" },
        "tag":            { "type": "keyword" },
        "date":           { "type": "date", "format": "yyyy-MM-dd||strict_date_optional_time" }
      }
    }
  }
}' > /dev/null
echo "  done"

echo "Creating OpenSearch Dashboards index patterns..."
declare -A INDEX_PATTERNS=(
  ["scans-*"]="submission_utc"
  ["screenshots-*"]="submission_utc"
  ["resources-*"]="last_seen_utc"
  ["domains*"]="last_seen_utc"
  ["servers*"]="last_seen_utc"
)
for pattern in "${!INDEX_PATTERNS[@]}"; do
  time_field="${INDEX_PATTERNS[$pattern]}"
  # A stable id makes the call idempotent: re-running overwrites instead of duplicating.
  id="webamon-${pattern//[^a-z]/}"
  curl -s -u "$AUTH" -X POST "${DASHBOARDS_URL}/api/saved_objects/index-pattern/${id}?overwrite=true" \
    -H "Content-Type: application/json" -H "osd-xsrf: true" \
    -d "{\"attributes\": {\"title\": \"${pattern}\", \"timeFieldName\": \"${time_field}\"}}" > /dev/null \
    && echo "  ${pattern} (time field: ${time_field})" \
    || echo "  failed to create ${pattern}"
done

echo "Setup complete."
