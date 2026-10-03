#!/bin/bash
# Security & Access Control Setup Script for TraceHunt ELK
set -e

ES_URL="${ES_URL:-http://localhost:9200}"

# Require admin authentication
if [ -z "$ES_ADMIN_USER" ] || [ -z "$ES_ADMIN_PASS" ]; then
  read -p "Enter Elasticsearch Admin Username [elastic]: " ES_ADMIN_USER
  ES_ADMIN_USER=${ES_ADMIN_USER:-elastic}
  read -sp "Enter Elasticsearch Admin Password: " ES_ADMIN_PASS
  echo ""
fi

# Fetch MCP user password from env or prompt securely
if [ -z "$MCP_USER_PASSWORD" ]; then
  read -sp "Enter Password for MCP Read-Only User: " MCP_USER_PASSWORD
  echo ""
  if [ -z "$MCP_USER_PASSWORD" ]; then
    echo "Error: MCP_USER_PASSWORD cannot be empty." >&2
    exit 1
  fi
fi

AUTH_HEADER="-u ${ES_ADMIN_USER}:${ES_ADMIN_PASS}"

echo "1. Creating MCP Read-Only Role..."
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$ES_URL/_security/role/mcp_read_only" \
  $AUTH_HEADER \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": ["monitor"],
    "indices": [
      {
        "names": ["tracehunt-*", "windows-security-*", "sysmon-*", "zeek-*", "logstash-*"],
        "privileges": ["read", "view_index_metadata"]
      }
    ]
  }')

if [ "$response" -ne 200 ] && [ "$response" -ne 201 ]; then
  echo "Error: Failed to create MCP read-only role (HTTP status: $response)" >&2
  exit 1
fi

echo "2. Creating MCP Server User..."
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$ES_URL/_security/user/mcp_user" \
  $AUTH_HEADER \
  -H "Content-Type: application/json" \
  -d "{
    \"password\": \"$MCP_USER_PASSWORD\",
    \"roles\": [\"mcp_read_only\"],
    \"full_name\": \"MCP Server Read-Only Account\",
    \"email\": \"mcp@tracehunt.local\"
  }")

if [ "$response" -ne 200 ] && [ "$response" -ne 201 ]; then
  echo "Error: Failed to create MCP server user (HTTP status: $response)" >&2
  exit 1
fi

echo "3. Applying Index Template..."
response=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$ES_URL/_index_template/tracehunt_template" \
  $AUTH_HEADER \
  -H "Content-Type: application/json" \
  -d @index_template.json)

if [ "$response" -ne 200 ] && [ "$response" -ne 201 ]; then
  echo "Error: Failed to apply index template (HTTP status: $response)" >&2
  exit 1
fi

echo "Security and Index Template setup complete!"
