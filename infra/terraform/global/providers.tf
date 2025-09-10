variable "aws_profile" {
  type    = string
  default = "default"
}

variable "aws_region" {
  type    = string
  default = "us-west-2"
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}


