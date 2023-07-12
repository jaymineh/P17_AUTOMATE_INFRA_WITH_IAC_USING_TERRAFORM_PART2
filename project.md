# Automate Infrastructure With IAC Using Terraform Part 2

**Step 1 - Create VPC, Private & Public Subnet**
---

- Create a new file called `main.tf`. This file will host the subnet & VPC configuration. Insert code below to declare the intended AWS region and get the list of AZs.

```
#Get list of AZ
data "aws_availability_zones" "available" {
  state = "available"
}

provider "aws" {
    region = var.region
}
```

- Insert code below to create the VPC for the project.

```
# Create VPC
resource "aws_vpc" "pbl" {
    cidr_block = var.vpc_cidr
    enable_dns_hostnames = var.enable_dns_support
    enable_dns_support = var.enable_dns_hostnames
    tags = {
      Name = "pbl"
    }
}
```

- Use the code below to create the private subnets.
```
# Create private subnets
resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.pbl.id
  count      = var.preferred_number_of_private_subnets == null ? length(data.aws_availability_zones.available.names) : var.preferred_number_of_private_subnets
  cidr_block = "10.0.${count.index + 40}.0/24"
  availability_zone = random_shuffle.az_list.result[count.index]

  tags = {
    Name = "privateSubnet${count.index + 1}"
  }
}
```
*The random_shuffle argument in the above code block is used to randomize the list of availabilty zones for setting up the private subnet. Depending on the AZ used, it may mead to errors when trying to deploy the private subnet*

- Use the code below to create the public subnets.
```
# Create public subnets
resource "aws_subnet" "public" {
  count = var.preferred_number_of_public_subnets == null ? length(data.aws_availability_zones.available.names) : var.preferred_number_of_public_subnets
  vpc_id = aws_vpc.pbl.id
  cidr_block = "10.0.${count.index + 20}.0/24"
  #cidr_block = cidrsubnet(var.vpc_cidr, 4, count.index)
  map_public_ip_on_launch = true
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Name = "publicSubnet${count.index + 1}"
  }
}
```
