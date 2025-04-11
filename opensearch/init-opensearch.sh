#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Wait for OpenSearch to be fully ready
echo "Waiting for OpenSearch to be fully ready..."
until curl -s --fail -k -u admin:admin https://webamon-node1:9200/_cluster/health > /dev/null; do
  echo "Waiting for OpenSearch..."
  sleep 5
done

# Variables
OPENSEARCH_URL="https://webamon-node1:9200"
TEMPLATES_DIR="/app/templates"

# List of template names and their corresponding file names and index names
declare -A TEMPLATES=(
  ["scans_template"]="scans_template.json"
  ["resources_template"]="resources_template.json" 
  ["domains_template"]="domains_template.json"
  ["servers_template"]="servers_template.json"
  ["screenshots_template"]="screenshots_template.json"
)

# Mapping of template names to the indices they should create
declare -A INDEX_NAMES=(
  ["scans_template"]="scans"
  ["resources_template"]="resources"
  ["domains_template"]="domains"
  ["servers_template"]="servers"
  ["screenshots_template"]="screenshots"
)

echo "OpenSearch is up and ready to initialize indices!"

# Apply each template
for TPL_NAME in "${!TEMPLATES[@]}"; do
  TPL_FILE="${TEMPLATES[$TPL_NAME]}"
  TPL_PATH="${TEMPLATES_DIR}/${TPL_FILE}"

  if [ ! -f "$TPL_PATH" ]; then
    echo "ERROR: Template file not found at ${TPL_PATH}"
    exit 1
  fi

  # Check if the template already exists
  if curl -s --head --fail -k -u admin:admin "${OPENSEARCH_URL}/_index_template/${TPL_NAME}" > /dev/null; then
    echo "Index template ${TPL_NAME} already exists."
  else
    echo "Creating index template ${TPL_NAME} from ${TPL_FILE}..."
    response_code=$(curl -s -o /dev/null -w "%{http_code}" -k -u admin:admin -X PUT "${OPENSEARCH_URL}/_index_template/${TPL_NAME}" \
      -H "Content-Type: application/json" \
      -d @"${TPL_PATH}")

    if [ "$response_code" -ge 200 ] && [ "$response_code" -lt 300 ]; then
      echo "Index template ${TPL_NAME} created successfully (HTTP $response_code)."
    else
      echo "ERROR: Failed to create index template ${TPL_NAME} (HTTP $response_code)."
      # Optionally print the response body on error
      curl -k -u admin:admin -X PUT "${OPENSEARCH_URL}/_index_template/${TPL_NAME}" \
        -H "Content-Type: application/json" \
        -d @"${TPL_PATH}"
      exit 1 # Exit if template creation fails
    fi
  fi
done

# Now create the actual indices based on the templates
echo "Creating indices based on templates..."
for TPL_NAME in "${!INDEX_NAMES[@]}"; do
  INDEX_NAME="${INDEX_NAMES[$TPL_NAME]}"
  
  # Check if the index already exists
  if curl -s --head --fail -k -u admin:admin "${OPENSEARCH_URL}/${INDEX_NAME}" > /dev/null; then
    echo "Index ${INDEX_NAME} already exists."
  else
    echo "Creating index ${INDEX_NAME} using template ${TPL_NAME}..."
    # Remove the complex template data extraction - the template will apply automatically
    # TEMPLATE_DATA=$(cat ${TEMPLATES_DIR}/${TEMPLATES[$TPL_NAME]} | grep -v "index_patterns" | sed 's/"template"://')

    # Create the index with an empty body; the template settings/mappings will be applied
    response_code=$(curl -s -o /dev/null -w "%{http_code}" -k -u admin:admin -X PUT "${OPENSEARCH_URL}/${INDEX_NAME}" \
      -H "Content-Type: application/json" \
      -d '{}')

    if [ "$response_code" -ge 200 ] && [ "$response_code" -lt 300 ]; then
      echo "Index ${INDEX_NAME} created successfully (HTTP $response_code)."
    else
      echo "ERROR: Failed to create index ${INDEX_NAME} (HTTP $response_code)."
      # Print error details on failure
      curl -k -u admin:admin -X PUT "${OPENSEARCH_URL}/${INDEX_NAME}" \
        -H "Content-Type: application/json" \
        -d '{}'
      # Don't exit on index creation failure - try to create other indices
    fi
  fi
done

# --- Mapping Verification ---
echo "Verifying index mappings..."
MAPPING_VERIFICATION_FAILED=0 # Flag to track failures

for TPL_NAME in "${!INDEX_NAMES[@]}"; do
  INDEX_NAME="${INDEX_NAMES[$TPL_NAME]}"
  echo "Verifying mapping for index ${INDEX_NAME}..."

  # Define the jq query to check a specific field based on the index
  # We check for the existence and type of a representative field from each mapping
  JQ_QUERY=""
  EXPECTED_INFO="" # Description of what's being checked

  case "$INDEX_NAME" in
    "scans")
      # Check if 'request.response.port' exists and is an integer (as 'scan_data' is not in the template)
      JQ_QUERY=".${INDEX_NAME}.mappings.properties.request.properties.response.properties.port.type == \"integer\""
      EXPECTED_INFO="'request.response.port' type to be 'integer'"
      ;;
    "resources")
      # Check if 'sha256' exists and is a keyword (as 'resource_type' is not in the template)
      JQ_QUERY=".${INDEX_NAME}.mappings.properties.sha256.type == \"keyword\""
      EXPECTED_INFO="'sha256' type to be 'keyword'"
      ;;
    "domains")
      # Check if 'dns.A' exists and is an ip type
      JQ_QUERY=".${INDEX_NAME}.mappings.properties.dns.properties.A.type == \"ip\""
      EXPECTED_INFO="'dns.A' type to be 'ip'"
      ;;
    "servers")
      # Check if 'ip' exists and is an ip type (as 'services' is not in the template)
      JQ_QUERY=".${INDEX_NAME}.mappings.properties.ip.type == \"ip\""
      EXPECTED_INFO="'ip' type to be 'ip'"
      ;;
    "screenshots")
      # Check if 'screenshot' exists and is binary (as 'screenshot_data' is not in the template)
      JQ_QUERY=".${INDEX_NAME}.mappings.properties.screenshot.type == \"binary\""
      EXPECTED_INFO="'screenshot' type to be 'binary'"
      ;;
    *)
      echo "WARNING: No mapping verification defined for index ${INDEX_NAME}."
      continue # Skip verification for unknown indices
      ;;
  esac

  # Get the mapping and check using jq
  # Use -f to fail silently on non-2xx HTTP status (e.g., index not found)
  # Use -e to set exit code based on query result (0=true, 1=false/null)
  if curl -s -f -k -u admin:admin "${OPENSEARCH_URL}/${INDEX_NAME}/_mapping" | jq -e "$JQ_QUERY"; then
    echo "✅ Mapping verification successful for ${INDEX_NAME} (${EXPECTED_INFO})."
  else
    # Check if the index actually exists before declaring mapping failure
    if curl -s --head --fail -k -u admin:admin "${OPENSEARCH_URL}/${INDEX_NAME}" > /dev/null; then
         echo "❌ ERROR: Mapping verification failed for index ${INDEX_NAME}."
         echo "   Expected ${EXPECTED_INFO}, but the check failed."
         # Try to get the actual type or status of the field
         ACTUAL_STATUS=$(curl -s -k -u admin:admin "${OPENSEARCH_URL}/${INDEX_NAME}/_mapping" | jq -r "try (${JQ_QUERY% ==*}) catch \"path error\" | if . == null then \"field not found\" else type end")
         echo "   Actual status/type: ${ACTUAL_STATUS}"
         echo "   Retrieved mapping snapshot (top-level keys):"
         # Show just the relevant part of the mapping if possible, or a snippet
         curl -s -k -u admin:admin "${OPENSEARCH_URL}/${INDEX_NAME}/_mapping" | jq ".${INDEX_NAME}.mappings.properties | keys | .[]" | head -n 5 # Show top-level keys
         echo "   (Use 'docker logs <container_name>' and look above for full mapping if needed)"
    else
         echo "❌ ERROR: Index ${INDEX_NAME} does not seem to exist. Cannot verify mapping."
    fi
    MAPPING_VERIFICATION_FAILED=1 # Set failure flag
  fi
done

# Check if any verification failed
if [ "$MAPPING_VERIFICATION_FAILED" -ne 0 ]; then
  echo "ERROR: One or more index mapping verifications failed. Exiting."
  exit 1
fi

echo "✅ All index mappings verified successfully."
# --- End Mapping Verification ---

# Check if sandbox-reports index exists and delete it if it does
echo "Checking for and removing any sandbox-reports index (not needed)..."
if curl -s --head --fail -k -u admin:admin "${OPENSEARCH_URL}/sandbox-reports" > /dev/null; then
  echo "Found sandbox-reports index, deleting it as it's not needed..."
  curl -s -k -u admin:admin -X DELETE "${OPENSEARCH_URL}/sandbox-reports"
  echo "✅ sandbox-reports index deleted. Sandbox should use scans index directly."
else
  echo "No sandbox-reports index found. Good!"
fi

# List all indices to confirm creation
echo "Listing all indices..."
curl -s -k -u admin:admin "${OPENSEARCH_URL}/_cat/indices?v"

echo "OpenSearch sandbox index initialization complete."

# ---------------- Index Pattern Setup in OpenSearch Dashboards ----------------
echo "Creating index patterns in OpenSearch Dashboards..."

DASHBOARDS_URL="http://webamon-dashboards:5601"
DASHBOARDS_AUTH="admin:admin"
DASHBOARDS_HEADERS=(-H "Content-Type: application/json" -H "osd-xsrf: true")
DASHBOARDS_CURL_OPTS=(--insecure -u $DASHBOARDS_AUTH)

declare -A INDEX_PATTERNS=(
  ["scans*"]="submission_utc"
  ["screenshots*"]="submission_utc"
  ["domains*"]="last_seen_utc"
  ["servers*"]="last_seen_utc"
  ["resources*"]="last_seen_utc"
)

for pattern in "${!INDEX_PATTERNS[@]}"; do
  time_field="${INDEX_PATTERNS[$pattern]}"
  echo "Creating index pattern: $pattern (timeField: $time_field)"

  curl -s -X POST "${DASHBOARDS_URL}/api/saved_objects/index-pattern" \
    "${DASHBOARDS_CURL_OPTS[@]}" \
    "${DASHBOARDS_HEADERS[@]}" \
    -d "{
      \"attributes\": {
        \"title\": \"${pattern}\",
        \"timeFieldName\": \"${time_field}\"
      }
    }" || echo "⚠️ Failed to create index pattern: $pattern"

  echo -e "\n----------------------\n"
done

echo "✅ Index pattern setup complete."
# ------------------------------------------------------------------------------


# Start the API server 
exec "$@" 