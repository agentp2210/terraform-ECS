terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.63.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs            = ["us-east-1a", "us-east-1b"]
  public_subnets = ["10.0.0.0/24", "10.0.1.0/24"]

  tags = {
    Terraform = "true"
  }
}

resource "aws_security_group" "lb_sg" {
  name   = "lb_sg"
  vpc_id = module.vpc.vpc_id
  ingress {
    description = "http from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "lb_sg"
  }
}

resource "aws_lb" "ecs-alb" {
  name               = "ecs-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = toset(module.vpc.public_subnets)
}

resource "aws_lb_target_group" "ecs-tg" {
  name        = "ecs-tg"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_lb_listener" "ecs-alb" {
  load_balancer_arn = aws_lb.ecs-alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ecs-tg.arn
  }
}

resource "aws_ecr_repository" "nginx-ecr" {
  name                 = "nginx-ecr"
  image_tag_mutability = "MUTABLE"

  # image_scanning_configuration {
  #   scan_on_push = true
  # }
}

data "aws_iam_policy_document" "ecs-tasks-execution-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_tasks_execution_role" {
  name               = "ecs-task-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs-tasks-execution-role-policy.json
  # inline_policy {
  #   name = "ecs_execution_policy"

  #   policy = jsonencode({
  #     Version = "2012-10-17"
  #     Statement = [
  #       {
  #         Action = [
  #           "ecr:GetAuthorizationToken",
  #           "ecr:BatchCheckLayerAvailability",
  #           "ecr:GetDownloadUrlForLayer",
  #           "ecr:BatchGetImage",
  #           "logs:CreateLogStream",
  #           "logs:PutLogEvents"
  #         ],
  #         Effect   = "Allow"
  #         Resource = "*"
  #       },
  #     ]
  #   })
  # }
}

resource "aws_iam_role_policy_attachment" "ecs_tasks_execution_role" {
  role       = aws_iam_role.ecs_tasks_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_cluster" "nginx-cluster" {
  name = "nginx-cluster"
}

resource "aws_cloudwatch_log_group" "ecs-log" {
  name = "/ecs/nginx-definition"
}

resource "aws_ecs_task_definition" "nginx-def" {
  family = "nginx-definition"
  #   container_definitions = <<TASK_DEFINITION
  # [
  #   {
  #     "cpu": 10,
  #     "command": ["sleep", "10"],
  #     "entryPoint": ["/"],
  #     "environment": [
  #       {"name": "VARNAME", "value": "VARVAL"}
  #     ],
  #     "essential": true,
  #     "image": "jenkins",
  #     "memory": 128,
  #     "name": "jenkins",
  #     "portMappings": [
  #       {
  #         "containerPort": 80,
  #         "hostPort": 8080
  #       }
  # ]
  container_definitions = jsonencode([
    {
      name      = "nginx-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
          protocol      = "tcp"
        }
      ]
    }
  ])
  execution_role_arn       = aws_iam_role.ecs_tasks_execution_role.arn
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  requires_compatibilities = ["FARGATE"]
}

resource "aws_security_group" "ecs_sg" {
  name   = "ecs_sg"
  vpc_id = module.vpc.vpc_id
  ingress {
    description = "http from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description     = "http from anywhere"
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_sg.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "lb_sg"
  }
}

resource "aws_ecs_service" "nginx-service" {
  name            = "nginx-service"
  cluster         = aws_ecs_cluster.nginx-cluster.id
  task_definition = aws_ecs_task_definition.nginx-def.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  load_balancer {
    target_group_arn = aws_lb_target_group.ecs-tg.arn
    container_name   = "nginx-container"
    container_port   = 80
  }
  network_configuration {
    subnets          = toset(module.vpc.public_subnets)
    security_groups  = [aws_security_group.ecs_sg.id]
    assign_public_ip = true
  }
  lifecycle {
    ignore_changes = [desired_count, task_definition]
  }
}

output "execution-role-arn" {
  value = aws_iam_role.ecs_tasks_execution_role.arn
}