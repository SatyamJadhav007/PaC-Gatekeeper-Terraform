terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # No remote backend — this is a demo config, never applied to real infra
}

provider "aws" {
  region = "ap-south-1"

  # Skip credential validation so `terraform plan` can work in CI
  # without real AWS credentials when using -generate-config-out or mocks.
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  default_tags {
    tags = {}
  }
}
