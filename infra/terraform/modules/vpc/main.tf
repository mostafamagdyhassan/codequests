variable "name" {}
variable "cidr" {}
variable "azs" { type = list(string) }
variable "public_subnet_cidrs" { type = list(string) }
variable "private_subnet_cidrs" { type = list(string) }
variable "enable_nat" { type = bool  default = true }

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 3.0.0"

  name                 = var.name
  cidr                 = var.cidr
  azs                  = var.azs
  public_subnets       = var.public_subnet_cidrs
  private_subnets      = var.private_subnet_cidrs
  enable_nat_gateway   = var.enable_nat
  single_nat_gateway   = true
  tags = {
    "Name" = var.name
    "env"  = var.name
  }
}

output "vpc_id" {
  value = module.vpc.vpc_id
}
output "private_subnets" {
  value = module.vpc.private_subnets
}
output "public_subnets" {
  value = module.vpc.public_subnets
}
