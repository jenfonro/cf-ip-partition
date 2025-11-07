#!/usr/bin/env bash
set -euo pipefail

OUTPUT_PATH="${1:-ipinfo_lite.mmdb}"

if [[ -n "${IP_DB_DOWNLOAD_URL:-}" ]]; then
  DOWNLOAD_URL="${IP_DB_DOWNLOAD_URL}"
elif [[ -n "${IPINFO_TOKEN:-}" ]]; then
  DOWNLOAD_URL="https://ipinfo.io/data/free/ipinfo-lite.mmdb?token=${IPINFO_TOKEN}"
else
  echo "必须通过 IP_DB_DOWNLOAD_URL 或 IPINFO_TOKEN 提供数据库下载地址" >&2
  exit 1
fi

echo "下载 IP 数据库：${DOWNLOAD_URL}"
curl -fSL "${DOWNLOAD_URL}" -o "${OUTPUT_PATH}"
echo "数据库已保存至 ${OUTPUT_PATH}"
