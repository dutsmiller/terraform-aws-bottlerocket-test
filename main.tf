provider "aws" {
  region = "us-east-1"
}

variable "email" {
  description = "email value for tagging"
  type        = string
}

variable "purpose" {
  description = "purpose value for tagging"
  type        = string
}

variable "bottlerocket_version" {
  description = "version of bottlerocket os"
  type        = string
  default     = "1.1.2"
}

locals {
  tags = {
    owner_email   = var.email
    support_email = var.email
    purpose       = var.purpose
  }

  user_data = <<-EOT
    [settings.host-containers.admin]
    enabled = true
  EOT
    #[settings.host-containers.nginx]
    #enabled = true
    #source = "registry.hub.docker.com/library/nginx
    #superpowered = false
}

data "aws_ssm_parameter" "bottlerocket_ami" {
  name = "/aws/service/bottlerocket/aws-ecs-1/arm64/${var.bottlerocket_version}/image_id"
}

data "http" "my_ip" {
  url = "https://ifconfig.me"
}

data "aws_vpc" "default" {
  default = true
}


resource "random_string" "random" {
  length  = 8
  number  = false
  special = false
}

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "ssh_private_key" {
  filename = "${path.module}/web.pem"
  content  = tls_private_key.ssh.private_key_pem
  file_permission = "0600"
}

resource "aws_key_pair" "kp" {
  key_name   = random_string.random.result
  public_key = tls_private_key.ssh.public_key_openssh
  tags       = local.tags
}

resource "aws_security_group" "sg" {
  name        = random_string.random.result
  description = "Allow SSH and HTTP"
  vpc_id      = data.aws_vpc.default.id

  tags = merge({ Name = "${random_string.random.result} - ${local.tags.purpose}" }, local.tags)

  ingress {
    description = "SSH from TF IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${data.http.my_ip.body}/32"]
  }

  egress {
    description = "Internet access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_iam_role" "web" {
  name = random_string.random.result

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = local.tags
}

data "aws_iam_policy" "ecr_read_only" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "ecr_read_only" {
  role       = aws_iam_role.web.name
  policy_arn = data.aws_iam_policy.ecr_read_only.arn
}

resource "aws_iam_instance_profile" "web" {
  name = random_string.random.result
  role = aws_iam_role.web.name
  tags = local.tags
}

resource "aws_instance" "web" {
  ami           = data.aws_ssm_parameter.bottlerocket_ami.value
  instance_type = "t4g.micro"
  key_name      = aws_key_pair.kp.key_name

  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.sg.id]

  iam_instance_profile = aws_iam_instance_profile.web.name

  user_data_base64 = base64encode(local.user_data)

  tags = merge({ Name = "${random_string.random.result} - ${local.tags.purpose}" }, local.tags)
}

output "instance_id" {
  value = aws_instance.web.id
}

output "instance_name" {
  value = "${random_string.random.result} - ${var.purpose}"
}

output "ssh_command" {
  value = "ssh -i web.pem ec2-user@${aws_instance.web.public_ip}"
}
