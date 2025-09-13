# TFLint configuration for showcase project
config {
  call_module_type = "all"
  force = false
  disabled_by_default = false
}

# Azure rules - disabled for showcase as many require production-specific settings
plugin "azurerm" {
    enabled = false  # Disabled to avoid production-specific warnings in showcase
    version = "0.20.0"
    source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

# Core Terraform rules - enabled for code quality
rule "terraform_deprecated_index" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}

rule "terraform_comment_syntax" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = false # Relaxed for showcase
}

rule "terraform_documented_variables" {
  enabled = false # Relaxed for showcase
}

rule "terraform_typed_variables" {
  enabled = true
}

rule "terraform_module_pinned_source" {
  enabled = false # Relaxed for showcase - using local modules
}

rule "terraform_naming_convention" {
  enabled = false # Relaxed for showcase
}

rule "terraform_required_version" {
  enabled = true
}

rule "terraform_required_providers" {
  enabled = true
}

rule "terraform_standard_module_structure" {
  enabled = false # Relaxed for showcase
}
