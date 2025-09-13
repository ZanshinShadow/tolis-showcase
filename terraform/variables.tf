# Input Variables for Terraform Configuration

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "tolis-showcase"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "East US"
}

variable "location_short" {
  description = "Short name for Azure region"
  type        = string
  default     = "eus"
}

variable "owner" {
  description = "Owner of the resources for tagging"
  type        = string
  default     = "System Engineering Team"
}

variable "cost_center" {
  description = "Cost center for billing"
  type        = string
  default     = "IT-Infrastructure"
}