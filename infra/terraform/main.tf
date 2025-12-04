# Terraform configuration for Agentic Bug Bounty Infrastructure
# Deploys: EKS cluster, SQS queues, S3 bucket, IAM roles

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
  
  # Uncomment for remote state storage
  # backend "s3" {
  #   bucket = "your-terraform-state-bucket"
  #   key    = "agentic-bugbounty/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "agentic-bugbounty"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "agentic-bugbounty"
}

variable "node_instance_types" {
  description = "EC2 instance types for EKS nodes"
  type        = list(string)
  default     = ["t3.medium", "t3.large"]
}

variable "min_nodes" {
  description = "Minimum number of nodes (can be 0 with Fargate)"
  type        = number
  default     = 0
}

variable "max_nodes" {
  description = "Maximum number of nodes"
  type        = number
  default     = 10
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "prod"  # Cost optimization for non-prod
  enable_dns_hostnames   = true
  enable_dns_support     = true

  # Tags required for EKS
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

# -----------------------------------------------------------------------------
# EKS Cluster
# -----------------------------------------------------------------------------

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.28"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Enable public endpoint for kubectl access (restrict in prod)
  cluster_endpoint_public_access = true

  # EKS Managed Node Group with autoscaling
  eks_managed_node_groups = {
    workers = {
      name           = "scan-workers"
      instance_types = var.node_instance_types
      
      min_size     = var.min_nodes
      max_size     = var.max_nodes
      desired_size = var.min_nodes  # Start with minimum, KEDA will scale

      # Spot instances for cost savings (scans are interruptible)
      capacity_type = "SPOT"
      
      labels = {
        workload = "scan-jobs"
      }
      
      taints = []
    }
  }

  # Fargate profile for serverless execution (alternative to managed nodes)
  fargate_profiles = {
    scan-jobs = {
      name = "scan-jobs"
      selectors = [
        {
          namespace = "scan-workers"
          labels = {
            "app.kubernetes.io/component" = "scan-worker"
          }
        }
      ]
    }
  }

  # IRSA for pod-level AWS permissions
  enable_irsa = true
}

# -----------------------------------------------------------------------------
# SQS Queues (Job Queues)
# -----------------------------------------------------------------------------

# Main job queue
resource "aws_sqs_queue" "scan_jobs" {
  name                       = "${var.cluster_name}-scan-jobs"
  visibility_timeout_seconds = 1800  # 30 minutes (max scan time)
  message_retention_seconds  = 86400 # 1 day
  receive_wait_time_seconds  = 20    # Long polling
  
  # Dead letter queue for failed jobs
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.scan_jobs_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue" "scan_jobs_dlq" {
  name                      = "${var.cluster_name}-scan-jobs-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# High priority queue for quick scans
resource "aws_sqs_queue" "scan_jobs_priority" {
  name                       = "${var.cluster_name}-scan-jobs-priority"
  visibility_timeout_seconds = 600  # 10 minutes
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 10
}

# Results notification queue
resource "aws_sqs_queue" "scan_results" {
  name                      = "${var.cluster_name}-scan-results"
  message_retention_seconds = 86400
}

# -----------------------------------------------------------------------------
# S3 Bucket (Results Storage)
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "scan_results" {
  bucket = "${var.cluster_name}-results-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "scan_results" {
  bucket = aws_s3_bucket.scan_results.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "scan_results" {
  bucket = aws_s3_bucket.scan_results.id

  rule {
    id     = "expire-old-results"
    status = "Enabled"

    # Move to Glacier after 30 days
    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    # Delete after 365 days
    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "scan_results" {
  bucket = aws_s3_bucket.scan_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------------------------------------------------------
# IAM Roles for Workers
# -----------------------------------------------------------------------------

# IAM role for scan worker pods (IRSA)
resource "aws_iam_role" "scan_worker" {
  name = "${var.cluster_name}-scan-worker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:scan-workers:scan-worker"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "scan_worker" {
  name = "${var.cluster_name}-scan-worker-policy"
  role = aws_iam_role.scan_worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ]
        Resource = [
          aws_sqs_queue.scan_jobs.arn,
          aws_sqs_queue.scan_jobs_priority.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = [
          aws_sqs_queue.scan_results.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.scan_results.arn,
          "${aws_s3_bucket.scan_results.arn}/*"
        ]
      }
    ]
  })
}

# IAM role for KEDA (to read SQS metrics)
resource "aws_iam_role" "keda" {
  name = "${var.cluster_name}-keda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:keda:keda-operator"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "keda" {
  name = "${var.cluster_name}-keda-policy"
  role = aws_iam_role.keda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl"
        ]
        Resource = [
          aws_sqs_queue.scan_jobs.arn,
          aws_sqs_queue.scan_jobs_priority.arn
        ]
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "sqs_queue_url" {
  description = "SQS job queue URL"
  value       = aws_sqs_queue.scan_jobs.url
}

output "sqs_priority_queue_url" {
  description = "SQS priority job queue URL"
  value       = aws_sqs_queue.scan_jobs_priority.url
}

output "s3_bucket" {
  description = "S3 results bucket name"
  value       = aws_s3_bucket.scan_results.id
}

output "worker_role_arn" {
  description = "IAM role ARN for scan workers"
  value       = aws_iam_role.scan_worker.arn
}

output "keda_role_arn" {
  description = "IAM role ARN for KEDA"
  value       = aws_iam_role.keda.arn
}

output "kubeconfig_command" {
  description = "Command to update kubeconfig"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

