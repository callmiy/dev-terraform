terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.26.0"
    }

    # docker = {
    #   source  = "kreuzwerker/docker"
    #   version = "2.20.2"
    # }
  }
}

provider "aws" {
  region = "us-east-1"

  shared_credentials_files = [
    "~/.aws/credentials"
  ]

  profile = "default"
}

# provider "docker" {}

variable "host_os" {
  type = string
}

variable "DOCKER_PASSWORD" {
  type = string
}


resource "aws_vpc" "mtc_vpc" {
  cidr_block           = "192.168.0.0/20"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "dev"
  }
}

resource "aws_subnet" "mtc_public_subnet" {
  vpc_id                  = aws_vpc.mtc_vpc.id
  cidr_block              = "192.168.0.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"

  tags = {
    Name = "dev-public"
  }
}

resource "aws_internet_gateway" "mtc_internet_gateway" {
  vpc_id = aws_vpc.mtc_vpc.id

  tags = {
    Name = "dev-igw"
  }
}

resource "aws_route_table" "mtc_public_rt" {
  vpc_id = aws_vpc.mtc_vpc.id

  # You may use this inline rule or dedicated aws_route resource below
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.mtc_internet_gateway.id
  }

  tags = {
    Name = "dev_public_rt"
  }
}

# You may use this dedicated resource or the inline rule above
# resource "aws_route" "mtc_public_r" {
#   route_table_id         = aws_route_table.mtc_public_rt.id
#   destination_cidr_block = "0.0.0.0/0"
#   gateway_id             = aws_internet_gateway.mtc_internet_gateway.id
# }

resource "aws_route_table_association" "mtc_public_assoc" {
  subnet_id      = aws_subnet.mtc_public_subnet.id
  route_table_id = aws_route_table.mtc_public_rt.id
}

resource "aws_security_group" "mtc_sg" {
  name        = "dev_sg"
  description = "Dev security group"
  vpc_id      = aws_vpc.mtc_vpc.id

  ingress {
    description = "Allow SSH from approved IP addresses"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [
      # "0.0.0.0/0"
      "176.236.70.90/32",
      "176.237.1.11/32"
    ]
  }

  ingress {
    description = "ICMP from anywhere"
    from_port   = 8
    to_port     = -1
    protocol    = "ICMP"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  tags = {
    Name = "dev_sg"
  }
}

# aws_ami = data source
# server_ami = where retrieved data will be written
data "aws_ami" "server_ami" {
  most_recent = true
  owners = [
    "099720109477"
  ]

  filter {
    name = "name"
    values = [
      "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"
    ]
  }
}

resource "aws_key_pair" "mtc_auth" {
  key_name   = "mtckey"
  public_key = file("~/.ssh/mtc-key.pub")
}

resource "aws_instance" "dev-node" {
  count         = 1
  ami           = data.aws_ami.server_ami.id
  instance_type = "t2.micro"
  availability_zone = "us-east-1a"
  key_name      = aws_key_pair.mtc_auth.id
  vpc_security_group_ids = [
    aws_security_group.mtc_sg.id
  ]
  subnet_id = aws_subnet.mtc_public_subnet.id
  # associate_public_ip_address = true

  # Script to run (after?) instance is provisioned?
  # Will fail on any command that writes to the file system. I found that
  # remote-exec does not have this limitation
  # user_data = file("user-data.tftpl")

  root_block_device {
    volume_size = 10
  }

  # Establishes connection to be used by all
  # generic remote provisioners (i.e. file/remote-exec)
  connection {
    type        = "ssh"
    user        = "ubuntu"
    host        = self.public_ip
    private_key = file("~/.ssh/mtc-key")
  }

  # copy source to destination
  provisioner "file" {
    source      = "~/.ssh/mtc-key.pub"
    destination = "/tmp/mtc-key.pub"
  }

  provisioner "file" {
    source      = "user-data.tftpl"
    destination = "/tmp/install-docker.sh"
  }

  provisioner "remote-exec" {
    inline = [
      # fail on first failed command - otherwise failure will apply only to
      # last command
      "set -o errexit",
      "mkdir -p ~/.ssh",
      "cat /tmp/mtc-key.pub >> ~/.ssh/authorized_keys",
      "chmod -R go= ~/.ssh",
      "chmod +x /tmp/install-docker.sh",
      "/tmp/install-docker.sh",
      "docker login --username samba6 --password ${var.DOCKER_PASSWORD} >/dev/null 2>&1",
      "docker pull samba6/kanmii:emojis__0.0.0",
      "docker run --detach --publish 8080:8080 samba6/kanmii:emojis__0.0.0",
    ]
  }

  provisioner "local-exec" {
    command = templatefile("${var.host_os}-ssh-config.tftpl", {
      host         = self.tags.Name,
      ip           = self.public_ip,
      user         = "ubuntu",
      identityfile = "~/.ssh/mtc-key"
    })

    # interpreter = ["bash", "-c"]
    interpreter = var.host_os == "linux" ? ["bash", "-c"] : ["Powershell", "-Command"]
  }

  tags = {
    Name = "dev-node"
  }
}
