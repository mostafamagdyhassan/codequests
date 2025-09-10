variable "cluster_name" {}
variable "vpc_id" {}
variable "subnet_ids" { type = list(string) }
variable "region" {}

module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  version         = ">= 19.0.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.27"   # adjust to current stable
  subnets         = var.subnet_ids
  vpc_id          = var.vpc_id

  manage_aws_auth = true

  node_groups = {
    ng1 = {
      desired_capacity = 2
      max_capacity     = 3
      min_capacity     = 1
      instance_type    = "t3.medium"
      key_name         = "" # optional
    }
  }

  # enable OIDC provider for IRSA
  enable_irsa = true

  tags = {
    Environment = var.cluster_name
  }
}

output "cluster_id" {
  value = module.eks.cluster_id
}
output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}
output "cluster_name" {
  value = module.eks.cluster_name
}
output "kubeconfig" {
  value = module.eks.kubeconfig
}
