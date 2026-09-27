#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image_name=${1:-fortbridge/libheif-grid-nextjs-rce:ubuntu2604}

docker build \
  --file "$repo_dir/containers/ubuntu2604/Dockerfile" \
  --tag "$image_name" \
  "$repo_dir"

docker image inspect "$image_name" --format '{{.Id}}'
