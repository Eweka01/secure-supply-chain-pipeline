terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state — S3 backend with DynamoDB locking.
  # Create the bucket and table before running terraform init.
  backend "s3" {
    bucket       = "supply-chain-tfstate-120430500058-use1"
    key          = "supply-chain/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}

provider "aws" {
  region = var.region
}
