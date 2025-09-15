variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name (prefix for resources)"
  type        = string
  default     = "devsecops-app"
}

variable "environment" {
  description = "Deployment environment (dev, prod)"
  type        = string
  default     = "prod"
}
