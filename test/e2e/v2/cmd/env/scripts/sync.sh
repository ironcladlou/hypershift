#!/usr/bin/env bash
set -euo pipefail

clusters_dir="clusters"
mkdir -p "${clusters_dir}"

# Sync each variant's cluster directory.
# CLUSTER_VARIANTS is a space-separated list of "variant:name" pairs
# set by the parent mise.toml environment.
for entry in ${CLUSTER_VARIANTS}; do
  variant="${entry%%:*}"
  name="${entry#*:}"

  dir="${clusters_dir}/${variant}"
  mkdir -p "${dir}"

  # Extract kubeconfig from the management cluster.
  echo "Syncing kubeconfig for ${variant} (${name})..."
  if ! "${HYPERSHIFT_BINARY}" create kubeconfig \
      --namespace="${HYPERSHIFT_NAMESPACE}" \
      --name="${name}" > "${dir}/kubeconfig" 2>/dev/null; then
    echo "WARNING: Failed to extract kubeconfig for ${name} (cluster may not be available yet)"
    rm -f "${dir}/kubeconfig"
    continue
  fi

  # Extract kubeadmin password.
  if password=$(kubectl get secret -n "${HYPERSHIFT_NAMESPACE}" "${name}-kubeadmin-password" \
      -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null); then
    echo "${password}" > "${dir}/kubeadmin-password"
  fi

  mise trust "${dir}" 2>/dev/null || true

  echo "  ${dir}/ ready"
done

echo "Sync complete. cd into clusters/<variant> to interact with a cluster."
