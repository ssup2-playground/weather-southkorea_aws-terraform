## Terraform
terraform {
    backend "s3" {
      bucket         = "tfstate-ssup2-playground"
      key            = "weather-southkorea/terraform.tfstate"
      region         = "ap-northeast-2"
      encrypt        = true
      dynamodb_table = "tfstate-ssup2-playground"
    }
}

