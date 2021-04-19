terraform {
  required_version = ">= 0.15"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }
}

variable "cluster_id" {
  type = string

  description = <<EOF
(internal) The OpenShift cluster id.

This cluster id must be of max length 27 and must have only alphanumeric or hyphen characters.
EOF

}

variable "cluster_domain" {
  type = string

  description = <<EOF
The domain of the cluster. It must NOT contain a trailing period. Some
DNS providers will automatically add this if necessary.

All the records for the cluster are created under this domain.
EOF

}

variable "base_domain_zone_id" {
  type = string

  description = <<EOF
The base DNS domain of the cluster. It must NOT contain a trailing period. Some
DNS providers will automatically add this if necessary.

Example: `hypershift.example.com`.

An NS record delegating to the cluster domain will be created in this zone.
EOF

}

variable "aws_region" {
  type        = string
  description = "The target AWS region for the cluster."
}

variable "aws_extra_tags" {
  type = map(string)

  description = <<EOF
(optional) Extra AWS tags to be applied to created resources.
Example: `{ "key" = "value", "foo" = "bar" }`
EOF

  default = {}
}

locals {
  tags = merge(
    { "kubernetes.io/cluster/${var.cluster_id}" = "owned" },
    var.aws_extra_tags,
  )
  description = "Created by HyperShift"
}

provider "aws" {
  region = var.aws_region
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_s3_bucket" "oidc_bucket" {
  bucket = var.cluster_id

  tags = merge(
    { "Name" = "${var.cluster_id}-oidc" },
    local.tags,
  )
}

resource "aws_iam_openid_connect_provider" "oidc_provider" {
  url = "https://s3.${var.aws_region}.amazonaws.com/${var.cluster_id}"

  client_id_list = [
    "openshift"
  ]

  thumbprint_list = [
    "A9D53002E97E00E043244F3D170D6F4C414104FD"
  ]

  tags = merge(
    { "Name" = "${var.cluster_id}-oidc" },
    local.tags,
  )
}

resource "aws_iam_role" "oidc_ingress_role" {
  name = "${var.cluster_id}-oidc-ingress"

  assume_role_policy = jsonencode({
    Version : "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated : aws_iam_openid_connect_provider.oidc_provider.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "s3.${var.aws_region}.amazonaws.com/${var.cluster_id}:sub" = "system:serviceaccount:openshift-ingress-operator:ingress-operator"
          }
        }
      }
    ]
  })

  inline_policy {
    name = "${var.cluster_id}-oidc-ingress"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "elasticloadbalancing:DescribeLoadBalancers",
            "route53:ListHostedZones",
            "route53:ChangeResourceRecordSets",
            "tag:GetResources"
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }

  tags = merge(
    { "Name" = "${var.cluster_id}-oidc-ingress" },
    local.tags,
  )
}

resource "aws_iam_role" "oidc_registry_role" {
  name = "${var.cluster_id}-oidc-registry"

  assume_role_policy = jsonencode({
    Version : "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated : aws_iam_openid_connect_provider.oidc_provider.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "s3.${var.aws_region}.amazonaws.com/${var.cluster_id}:sub" = "system:serviceaccount:openshift-image-registry:cluster-image-registry-operator"
          }
        }
      }
    ]
  })

  inline_policy {
    name = "${var.cluster_id}-oidc-registry"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "s3:CreateBucket",
            "s3:DeleteBucket",
            "s3:PutBucketTagging",
            "s3:GetBucketTagging",
            "s3:PutBucketPublicAccessBlock",
            "s3:GetBucketPublicAccessBlock",
            "s3:PutEncryptionConfiguration",
            "s3:GetEncryptionConfiguration",
            "s3:PutLifecycleConfiguration",
            "s3:GetLifecycleConfiguration",
            "s3:GetBucketLocation",
            "s3:ListBucket",
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:ListBucketMultipartUploads",
            "s3:AbortMultipartUpload",
            "s3:ListMultipartUploadParts",
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }

  tags = merge(
    { "Name" = "${var.cluster_id}-oidc-registry" },
    local.tags,
  )
}

resource "aws_iam_role" "oidc_csi_role" {
  name = "${var.cluster_id}-oidc-csi"

  assume_role_policy = jsonencode({
    Version : "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated : aws_iam_openid_connect_provider.oidc_provider.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "s3.${var.aws_region}.amazonaws.com/${var.cluster_id}:sub" = "system:serviceaccount:openshift-cluster-csi-drivers:aws-ebs-csi-driver-operator"
          }
        }
      }
    ]
  })

  inline_policy {
    name = "${var.cluster_id}-oidc-csi"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "ec2:AttachVolume",
            "ec2:CreateSnapshot",
            "ec2:CreateTags",
            "ec2:CreateVolume",
            "ec2:DeleteSnapshot",
            "ec2:DeleteTags",
            "ec2:DeleteVolume",
            "ec2:DescribeInstances",
            "ec2:DescribeSnapshots",
            "ec2:DescribeTags",
            "ec2:DescribeVolumes",
            "ec2:DescribeVolumesModifications",
            "ec2:DetachVolume",
            "ec2:ModifyVolume",
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }

  tags = merge(
    { "Name" = "${var.cluster_id}-oidc-csi" },
    local.tags,
  )
}

resource "aws_iam_role" "worker_role" {
  name = "${var.cluster_id}-worker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Principal = {
          Service : ["ec2.amazonaws.com"]
        }
        Action = [
          "sts:AssumeRole",
        ]
        Effect = "Allow"
      },
    ]
  })

  inline_policy {
    name = "${var.cluster_id}-worker"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "ec2:DescribeInstance",
            "ec2:DescribeRegions",
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }

  tags = merge(
    { "Name" = "${var.cluster_id}-worker" },
    local.tags,
  )
}

resource "aws_iam_instance_profile" "worker_instance_profile" {
  name = "${var.cluster_id}-worker"
  role = aws_iam_role.worker_role.name
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(
    { "Name" = "${var.cluster_id}-vpc" },
    local.tags,
  )
}

resource "aws_vpc_dhcp_options" "main" {
  # TODO: Lookup from a map or figure out how to use defaults
  domain_name         = "ec2.internal"
  domain_name_servers = ["AmazonProvidedDNS"]

  tags = merge(
    { "Name" = "${var.cluster_id}-dhcp" },
    local.tags,
  )
}

resource "aws_vpc_dhcp_options_association" "main" {
  vpc_id          = aws_vpc.main.id
  dhcp_options_id = aws_vpc_dhcp_options.main.id
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.128.0/20"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = merge(
    { "Name" = "${var.cluster_id}-private" },
    local.tags,
  )
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.0.0/20"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = merge(
    { "Name" = "${var.cluster_id}-public" },
    local.tags,
  )
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    { "Name" = "${var.cluster_id}-igw" },
    local.tags,
  )
}

resource "aws_eip" "nat" {
  vpc = true
  tags = merge(
    { "Name" = "${var.cluster_id}-nat-gw" },
    local.tags,
  )
}

resource "aws_nat_gateway" "gw" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = merge(
    { "Name" = "${var.cluster_id}-nat-gw" },
    local.tags,
  )
}

resource "aws_security_group" "worker" {
  name        = "allow_tls"
  description = "HyperShift worker security group"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "50"
  }

  ingress {
    from_port   = "-1"
    to_port     = "-1"
    protocol    = "icmp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  ingress {
    from_port = 6081
    to_port   = 6081
    protocol  = "udp"
  }

  ingress {
    from_port = 500
    to_port   = 500
    protocol  = "udp"
  }

  ingress {
    from_port = 4500
    to_port   = 4500
    protocol  = "udp"
  }

  ingress {
    from_port = 9000
    to_port   = 9999
    protocol  = "tcp"
  }

  ingress {
    from_port = 9000
    to_port   = 9999
    protocol  = "udp"
  }

  ingress {
    from_port = 10250
    to_port   = 10250
    protocol  = "tcp"
  }

  ingress {
    from_port = 30000
    to_port   = 32767
    protocol  = "tcp"
  }

  ingress {
    from_port = 30000
    to_port   = 32767
    protocol  = "udp"
  }

  tags = merge(
    { "Name" = "${var.cluster_id}-worker" },
    local.tags,
  )
}
