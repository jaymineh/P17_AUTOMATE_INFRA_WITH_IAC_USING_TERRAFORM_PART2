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
  map_public_ip_on_launch = true
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Name = "publicSubnet${count.index + 1}"
  }
}
```

**Step 2 - Create Internet Gateway**
---

- Create a file called `interget-gw.tf`. This will host the configuration for the internet gateway. Insert the code below:

```
resource "aws_internet_gateway" "ig" {
  vpc_id = aws_vpc.pbl.id

  tags = merge(
    var.tags,
    {
      Name = format("%s-%s-%s!", var.name, aws_vpc.pbl.id, "IG")
    },
  )
}
```

**Step 3 - Create NAT Gateway & EIP**
---

- Create a file called `nat-gw.tf`. The following code will create a NAT gateway and attach an elastic IP to it. The NAT gateway and EIP are made to depend on the internet gateway to ensure it is created before the NAT gateway and EIP are done.

```
# Create EIP
resource "aws_eip" "nat_eip" {
  domain        = "vpc"
  depends_on = [aws_internet_gateway.ig]

  tags = merge(
    var.tags,
    {
      Name = format("%s-EIP-%s", var.name, var.environment)
    },
  )
}

# Create Nat-Gateway
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = element(aws_subnet.public.*.id, 0)
  depends_on    = [aws_internet_gateway.ig]

  tags = merge(
    var.tags,
    {
      Name = format("%s-NAT-%s", var.name, var.environment)
    },
  )
}
```

**Step 4 - Creating Routes**
---

- Create a file that will be used to create routes for both private and public subnets. The file is named `routes.tf`.

```
# create private route table
resource "aws_route_table" "private-rtb" {
  vpc_id = aws_vpc.pbl.id

  tags = merge(
    var.tags,
    {
      Name = format("%s-PRIVATE-ROUTE-TABLE-%s", var.name, var.environment)
    },
  )
}

# create public route table
resource "aws_route_table" "public-rtb" {
  vpc_id = aws_vpc.pbl.id

  tags = merge(
    var.tags,
    {
      Name = format("%s-PUBLIC-ROUTE-TABLE-%s", var.name, var.environment)
    },
  )
}

# create route for the private route table and attatch a nat gateway to it
resource "aws_route" "private-rtb-route" {
  route_table_id         = aws_route_table.private-rtb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_nat_gateway.nat.id
}


# create route for the public route table and attach the internet gateway
resource "aws_route" "public-rtb-route" {
  route_table_id         = aws_route_table.public-rtb.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.ig.id
}

# associate all private subnets to the private route table
resource "aws_route_table_association" "private-subnets-assoc" {
  count          = length(aws_subnet.private[*].id)
  subnet_id      = element(aws_subnet.private[*].id, count.index)
  route_table_id = aws_route_table.private-rtb.id
}

# associate all public subnets to the public route table
resource "aws_route_table_association" "public-subnets-assoc" {
  count          = length(aws_subnet.public[*].id)
  subnet_id      = element(aws_subnet.public[*].id, count.index)
  route_table_id = aws_route_table.public-rtb.id
}
```

**Step 5 - Create IAM Roles**
---

*Here, an IAM role is created and passed to the EC2 instances to give them access to specific resources. This is achieved by creating an `AssumeRole` and `AssumeRole` policy.*

- Create a file called `roles.tf` and enter the following code:

```
# Create role
resource "aws_iam_role" "ec2_instance_role" {
  name = "ec2_instance_role"
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
  tags = {
    Name        = "aws assume role"
    Environment = var.environment
  }
}

# Create policy
resource "aws_iam_policy" "policy" {
  name        = "ec2_instance_policy"
  description = "A test policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]

  })

  tags = {
    Name        = "aws assume policy"
    Environment = var.environment
  }
}

# Attach policy to IAM role
resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.ec2_instance_role.name
  policy_arn = aws_iam_policy.policy.arn
}

#Create instance profile and interpolate IAM role
resource "aws_iam_instance_profile" "ip" {
  name = "aws_instance_profile_test"
  role = aws_iam_role.ec2_instance_role.name
}
```

**Step 6 - Create Security Groups**
---

- Create a new file called `security.tf`. Enter the code below to create a security group for the internal and external load balancer, the bastion server, nginx, tooling and wordpress server and the data layer. Input the code below:

```
# security group for alb, to allow acess from anywhere on port 80 & 443.
resource "aws_security_group" "ext-alb-sg" {
  name        = "ext-alb-sg"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.pbl.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "EXT-ALB-SG"
  }
}


# Security group for bastion to allow access into the bastion host from your IP
resource "aws_security_group" "bastion-sg" {
  name        = "bastion-sg"
  description = "Allow incoming HTTP connections."
  vpc_id      = aws_vpc.pbl.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "BASTION-SG"
    Environment = var.environment
  }
}

# Security group for nginx reverse proxy to allow access only from the external load balancer and bastion instance 
resource "aws_security_group" "nginx-sg" {
  name   = "nginx-sg"
  vpc_id = aws_vpc.pbl.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "NGINX-SG"
  }
}

resource "aws_security_group_rule" "inbound-nginx-https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ext-alb-sg.id
  security_group_id        = aws_security_group.nginx-sg.id
}

resource "aws_security_group_rule" "inbound-nginx-http-80" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ext-alb-sg.id
  security_group_id        = aws_security_group.nginx-sg.id
}

resource "aws_security_group_rule" "inbound-bastion-ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion-sg.id
  security_group_id        = aws_security_group.nginx-sg.id
}

# Security group for internal alb, to have access only from nginx reverse proxy server
resource "aws_security_group" "int-alb-sg" {
  name   = "int-alb-sg"
  vpc_id = aws_vpc.pbl.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "INT-ALB-SG"
  }
}

resource "aws_security_group_rule" "inbound-ialb-https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nginx-sg.id
  security_group_id        = aws_security_group.int-alb-sg.id
}

# Security group for webservers, to have access only from the internal load balancer and bastion instance
resource "aws_security_group" "webserver-sg" {
  name   = "webserver-sg"
  vpc_id = aws_vpc.pbl.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "WEBSERVER-SG"
  }
}

resource "aws_security_group_rule" "inbound-webserver-https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.int-alb-sg.id
  security_group_id        = aws_security_group.webserver-sg.id
}

resource "aws_security_group_rule" "inbound-webserver-ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion-sg.id
  security_group_id        = aws_security_group.webserver-sg.id
}

# Security group for datalayer to allow traffic from webserver on nfs and mysql port ann bastion host on mysql
resource "aws_security_group" "datalayer-sg" {
  name   = "datalayer-sg"
  vpc_id = aws_vpc.pbl.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "DATALAYER-SG"
  }
}

resource "aws_security_group_rule" "inbound-nfs-port" {
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.webserver-sg.id
  security_group_id        = aws_security_group.datalayer-sg.id
}

resource "aws_security_group_rule" "inbound-mysql-bastion" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion-sg.id
  security_group_id        = aws_security_group.datalayer-sg.id
}

resource "aws_security_group_rule" "inbound-mysql-webserver" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.webserver-sg.id
  security_group_id        = aws_security_group.datalayer-sg.id
}
```

*The `aws_security_group_rule` is used to reference another security group*

**Step 7 - Setup Variables**
---

*Since we have been using several variables in the previous steps, we would need to declare these variables in a file that Terraform will read from.*

- Create new file called `variables.tf`. Paste in the code below:

```
variable "region" {
      default = "us-east-1"
}

variable "vpc_cidr" {
    default = "10.0.0.0/16"
}

variable "enable_dns_support" {
    default = "true"
}

variable "enable_dns_hostnames" {
    default ="true" 
}

  variable "preferred_number_of_public_subnets" {
      default = null
}

variable "preferred_number_of_private_subnets" {
  type        = number
  description = "Number of private subnets"
}

variable "name" {
  type    = string
  default = "ACS"
}

variable "tags" {
  type        = map(string)
  description = "A mapping of tags to assign to all resources"
  default     = {}
}

variable "environment" {
  type        = string
  description = "Environment"
}

variable "ami" {
  type        = string
  description = "AMI ID for the launch template"
}

variable "keypair" {
  type        = string
  description = "Key pair for the instances"
}

variable "account_no" {
  type        = number
  description = "the account number"
}

variable "master-username" {
  type        = string
  description = "RDS admin username"
}

variable "master-password" {
  type        = string
  description = "RDS master password"
}
```

- Create another file called `terraform.tfvars` that would assign values to the variables and paste in the code below:

```
region = "us-east-1"

vpc_cidr = "10.0.0.0/16" 

enable_dns_support = "true" 

enable_dns_hostnames = "true"  

preferred_number_of_public_subnets = 2

preferred_number_of_private_subnets = 4

tags = {
  Owner-Email = "jemine@iceglobalv.onmicrosoft.com"
  Managed-By  = "Terraform"
}

environment = "DEV"

ami = "ami-026ebd4cfe2c043b2"

keypair = "Jemine-EC4"

account_no = 894194274688

master-username = "admin"

master-password = "password"
```

**Step 7 - Create Certificate From Amazon Certificate Manager**
---

- Create a new file called `cert.tf` and enter the following code to create and validate a certificate on AWS.

```
# The entire section create a certiface, public zone, and validate the certificate using DNS method

# Create hosting zone
resource "aws_route53_zone" "jmn_hosted_zone" {
  name = "constanet.wip.la"
}

# Create the certificate using a wildcard for all the domains created in projectaws.xyz
resource "aws_acm_certificate" "jmn_cert" {
  domain_name       = "*.constanet.wip.la"
  validation_method = "DNS"
}

# calling the hosted zone
data "aws_route53_zone" "jmn_hosted_zone" {
  name         = "constanet.wip.la"
  private_zone = false
  depends_on = [aws_route53_zone.jmn_hosted_zone]
}

# selecting validation method
resource "aws_route53_record" "jmn_record" {
  for_each = {
    for dvo in aws_acm_certificate.jmn_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } 

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.jmn_hosted_zone.zone_id
}

# validate the certificate through DNS method
resource "aws_acm_certificate_validation" "jmn_validation" {
  certificate_arn         = aws_acm_certificate.jmn_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.jmn_record : record.fqdn]
}

# create records for tooling
resource "aws_route53_record" "tooling" {
  zone_id = data.aws_route53_zone.jmn_hosted_zone.zone_id
  name    = "tooling.constanet.wip.la"
  type    = "A"

  alias {
    name                   = aws_lb.ext-alb.dns_name
    zone_id                = aws_lb.ext-alb.zone_id
    evaluate_target_health = true
  }
}

# create records for wordpress
resource "aws_route53_record" "wordpress" {
  zone_id = data.aws_route53_zone.jmn_hosted_zone.zone_id
  name    = "wordpress.constanet.wip.la"
  type    = "A"

  alias {
    name                   = aws_lb.ext-alb.dns_name
    zone_id                = aws_lb.ext-alb.zone_id
    evaluate_target_health = true
  }
}
```

