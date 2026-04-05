# ECR repository for the supply-chain-app image.
# Image scanning on push catches known CVEs at the registry level.
resource "aws_ecr_repository" "app" {
  name                 = "supply-chain-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Name = "supply-chain-app" }
}

# Keep only the 10 most recent images — prevents unbounded storage growth.
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}
