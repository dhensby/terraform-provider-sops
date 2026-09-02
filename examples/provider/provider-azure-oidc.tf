provider "sops" {
  azure_keyvault = {
    use_oidc = true

    # Both default to ARM_CLIENT_ID / ARM_TENANT_ID when unset.
    client_id = var.client_id
    tenant_id = var.tenant_id
  }
}

data "sops_file" "demo_secret" {
  source_file = "demo-secret.enc.yaml"
}
