provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# VPC
module "vpc" {
  source = "../../modules/vpc"
  name   = "${var.env}-vpc"
  cidr   = var.vpc_cidr
  azs    = var.azs
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  enable_nat = true
}

# EKS
module "eks" {
  source = "../../modules/eks"
  cluster_name = "${var.env}-eks"
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnets
  region       = var.aws_region
}

# Output kubeconfig
output "cluster_name" {
  value = module.eks.cluster_name
}
output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}
output "kubeconfig" {
  value = module.eks.kubeconfig
}
