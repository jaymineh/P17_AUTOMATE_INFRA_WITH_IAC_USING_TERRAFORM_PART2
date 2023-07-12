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

**Step 8 - Create App Load Balancer**
---

- Create a file called `alb.tf`. The code below would create an external facing load balanncer which balances traffic for the nginx servers.

```
# ----------------------------
#External Load balancer for reverse proxy nginx
#---------------------------------

resource "aws_lb" "ext-alb" {
  name            = "ext-alb"
  internal        = false
  security_groups = [aws_security_group.ext-alb-sg.id]
  subnets         = [aws_subnet.public[0].id, aws_subnet.public[1].id]

  tags = {
    Name = "ext-alb"
  }

  ip_address_type    = "ipv4"
  load_balancer_type = "application"
}
```

- Create a target group for the nginx server, which informs the ALB where to route traffic.

```
#--- create a target group for the external load balancer
resource "aws_lb_target_group" "nginx-tgt" {
  health_check {
    interval            = 10
    path                = "/healthstatus"
    protocol            = "HTTPS"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
  name        = "nginx-tgt"
  port        = 443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.pbl.id
}
```

- Create a listener for the nginx target group.

```
#--- create a listener for the load balancer
resource "aws_lb_listener" "nginx-listner" {
  load_balancer_arn = aws_lb.ext-alb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.jmn_validation.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nginx-tgt.arn
  }
}
```

- Create a file called `output.tf` and paste in the code block below to output the DNS and target group name

```
output "alb_dns_name" {
  value = aws_lb.ext-alb.dns_name
}

output "alb_target_group_arn" {
  value = aws_lb_target_group.nginx-tgt.arn
}
```

- In the `alb.tf` file, add the following code to create an internal load balancer.

```
# ----------------------------
#Internal Load Balancers for webservers
#---------------------------------
resource "aws_lb" "int-alb" {
  name     = "int-alb"
  internal = true

  security_groups = [aws_security_group.int-alb-sg.id]

  subnets = [aws_subnet.private[0].id, aws_subnet.private[1].id]

  tags = {
    Name = "int-alb"
  }

  ip_address_type    = "ipv4"
  load_balancer_type = "application"
}
```

- Create target group for the wordpress and tooling server to inform the ALB where to route traffic.

```
# --- target group  for wordpress -------
resource "aws_lb_target_group" "wordpress-tgt" {
  health_check {
    interval            = 10
    path                = "/healthstatus"
    protocol            = "HTTPS"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }

  name        = "wordpress-tgt"
  port        = 443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.pbl.id
}

# --- target group for tooling -------
resource "aws_lb_target_group" "tooling-tgt" {
  health_check {
    interval            = 10
    path                = "/healthstatus"
    protocol            = "HTTPS"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }

  name        = "tooling-tgt"
  port        = 443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.pbl.id
}
```

- Create a listener for the target groups.

```
# For this aspect a single listener was created for the wordpress which is default,
# A rule was created to route traffic to tooling when the host header changes

resource "aws_lb_listener" "web-listener" {
  load_balancer_arn = aws_lb.int-alb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.jmn_validation.certificate_arn


  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress-tgt.arn
  }
}

# # listener rule for tooling target

resource "aws_lb_listener_rule" "tooling-listener" {
  listener_arn = aws_lb_listener.web-listener.arn
  priority     = 99

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tooling-tgt.arn
  }

  condition {
    host_header {
      values = ["tooling.constanet.wip.la"]
    }
  }
}
```

**Step 9 - Create Autoscaling Group**
---

- Create a new file called `asg-bastion-nginx.tf`. This will contain the configuration used to create an autoscaling group for the bastion and nginx server.

```
# Get list of availability zones
data "aws_availability_zones" "available-bastion" {
  state = "available"
}

# creating sns topic for all the auto scaling groups
resource "aws_sns_topic" "ACS-sns" {
  name = "Default_CloudWatch_Alarms_Topic"
}


# creating notification for all the auto scaling groups
resource "aws_autoscaling_notification" "aws_notifications" {
  group_names = [
    aws_autoscaling_group.bastion-asg.name,
    aws_autoscaling_group.nginx-asg.name,
    aws_autoscaling_group.wordpress-asg.name,
    aws_autoscaling_group.tooling-asg.name,
  ]
  notifications = [
    "autoscaling:EC2_INSTANCE_LAUNCH",
    "autoscaling:EC2_INSTANCE_TERMINATE",
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
    "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
  ]

  topic_arn = aws_sns_topic.ACS-sns.arn
}

resource "random_shuffle" "az_list" {
  input = data.aws_availability_zones.available-bastion.names
}

resource "aws_launch_template" "bastion-launch-template" {
  name                   = "bastion-launch-template"
  instance_type          = "t2.micro"
  image_id               = var.ami
  vpc_security_group_ids = [aws_security_group.bastion-sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name = var.keypair

  placement {
    availability_zone = "random_shuffle.az_list.result"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "bastion-launch-template"
    }
  }

  user_data = filebase64("${path.module}/bastion.sh")
}


# ---- Autoscaling for bastion  hosts

resource "aws_autoscaling_group" "bastion-asg" {
  name                      = "bastion-asg"
  max_size                  = 2
  min_size                  = 2
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2

  # Where you place in your subnet
  vpc_zone_identifier = [aws_subnet.public[0].id, aws_subnet.public[1].id]

  launch_template {
    id      = aws_launch_template.bastion-launch-template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "ACS-Bastion"
    propagate_at_launch = true
  }

}

resource "aws_launch_template" "nginx-launch-template" {
  name                   = "nginx-launch-template"
  instance_type          = "t2.micro"
  image_id               = var.ami
  vpc_security_group_ids = [aws_security_group.nginx-sg.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name = var.keypair

  placement {
    availability_zone = "random_shuffle.az_list.result"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "nginx-launch-template"
    }
  }

  user_data = filebase64("${path.module}/nginx.sh")
}


# ------ Autoscalaling group for reverse proxy nginx ---------

resource "aws_autoscaling_group" "nginx-asg" {
  name                      = "nginx-asg"
  max_size                  = 2
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1

  vpc_zone_identifier = [aws_subnet.public[0].id, aws_subnet.public[1].id]

  launch_template {
    id      = aws_launch_template.nginx-launch-template.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "ACS-nginx"
    propagate_at_launch = true
  }
}

# attaching autoscaling group of nginx to external load balancer
resource "aws_autoscaling_attachment" "asg_attachment_nginx" {
  autoscaling_group_name = aws_autoscaling_group.nginx-asg.id
  lb_target_group_arn   = aws_lb_target_group.nginx-tgt.arn
}
```

- Create `asg-wordpress-tooling.tf` and enter the following codes which would create launch templates and auto scaling groups for both the wordpress and tooling webserver.

```
# Launch template for wordpress
resource "aws_launch_template" "wordpress-launch-template" {
  name                   = "wordpress-launch-template"
  instance_type          = "t2.micro"
  image_id               = var.ami
  vpc_security_group_ids = [aws_security_group.webserver-sg.id]

  provisioner "local-exec" {
    command = "powershell.exe ${path.module}/wordpress.sh ${aws_efs_access_point.wordpress.id} ${aws_efs_file_system.ACS-efs.id}"
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name = var.keypair

  placement {
    availability_zone = "random_shuffle.az_list.result"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "wordpress-launch-template"
    }
  }

  user_data = filebase64("${path.module}/wordpress.sh")

}

# ---- Autoscaling for wordpress application
resource "aws_autoscaling_group" "wordpress-asg" {
  name                      = "wordpress-asg"
  max_size                  = 2
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2

  # Where you place in your subnet
  vpc_zone_identifier = [aws_subnet.private[0].id, aws_subnet.private[1].id]

  launch_template {
    id      = aws_launch_template.wordpress-launch-template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "ACS-wordpress"
    propagate_at_launch = true
  }

}

# attaching autoscaling group of wordpress to internal load balancer
resource "aws_autoscaling_attachment" "asg_attachment_wordpress" {
  autoscaling_group_name = aws_autoscaling_group.wordpress-asg.id
  lb_target_group_arn   = aws_lb_target_group.wordpress-tgt.arn
}

# launch template for tooling
resource "aws_launch_template" "tooling-launch-template" {
  name                   = "tooling-launch-template"
  instance_type          = "t2.micro"
  image_id               = var.ami
  vpc_security_group_ids = [aws_security_group.webserver-sg.id]

    provisioner "local-exec" {
    command = "powershell.exe ${path.module}/tooling.sh ${aws_efs_access_point.tooling.id} ${aws_efs_file_system.ACS-efs.id}"
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ip.id
  }

  key_name = var.keypair

  placement {
    availability_zone = "random_shuffle.az_list.result"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "tooling-launch-template"
    }
  }

  user_data = filebase64("${path.module}/tooling.sh")
}

# ---- Autoscaling for tooling 
resource "aws_autoscaling_group" "tooling-asg" {
  name                      = "tooling-asg"
  max_size                  = 2
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2

  # Where you place in your subnet
  vpc_zone_identifier = [aws_subnet.private[0].id, aws_subnet.private[1].id]

  launch_template {
    id      = aws_launch_template.tooling-launch-template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "ACS-tooling"
    propagate_at_launch = true
  }

}

# attaching autoscaling group of tooling application to internal loadbalancer
resource "aws_autoscaling_attachment" "asg_attachment_tooling" {
  autoscaling_group_name = aws_autoscaling_group.tooling-asg.id
  lb_target_group_arn   = aws_lb_target_group.tooling-tgt.arn
}
```

*The provisioner line has a command to dynamically get the EFS mount and access point values when it gets created. The EFS will not be created on the AWS console but by Terraform and the values will be delivered to where variales/placeholders are kept*

**Step 10 - Create Installation Scripts On Servers**
---

- Create `bastion.sh` file and insert the code below:

```
#!/bin/bash
yum install -y mysql
yum install -y git tmux
yum install -y ansible
```

- Create `nginx.sh` file and insert code below:

```
#!/bin/bash
yum install -y nginx
systemctl start nginx
systemctl enable nginx
git clone https://github.com/jaymineh/ACS-project-config.git
mv /ACS-project-config/reverse.conf /etc/nginx/
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf-distro
cd /etc/nginx/
touch nginx.conf
sed -n 'w nginx.conf' reverse.conf
systemctl restart nginx
rm -rf reverse.conf
rm -rf /ACS-project-config
```

- Create `wordpress.sh` and insert the following:

```
#!/bin/bash
mkdir /var/www/
sudo mount -t efs -o tls,accesspoint="$1" "$2":/ /var/www/
yum install -y httpd 
systemctl start httpd
systemctl enable httpd
yum module reset php -y
yum module enable php:remi-7.4 -y
yum install -y php php-common php-mbstring php-opcache php-intl php-xml php-gd php-curl php-mysqlnd php-fpm php-json
systemctl start php-fpm
systemctl enable php-fpm
wget http://wordpress.org/latest.tar.gz
tar xzvf latest.tar.gz
rm -rf latest.tar.gz
cp wordpress/wp-config-sample.php wordpress/wp-config.php
mkdir /var/www/html/
cp -R /wordpress/* /var/www/html/
cd /var/www/html/
touch healthstatus
sed -i "s/localhost/tcs-database.cgk2jcnauxqt.us-east-2.rds.amazonaws.com/g" wp-config.php 
sed -i "s/username_here/TCSadmin/g" wp-config.php 
sed -i "s/password_here/1234567890/g" wp-config.php 
sed -i "s/database_name_here/wordpressdb/g" wp-config.php 
chcon -t httpd_sys_rw_content_t /var/www/html/ -R
systemctl restart httpd
```

*In the sudo mount line, $1 & $2 are used as placeholders for the EFS mount points and access points. The values will be gotten when the `provisioner` line in `asg-wordpress-nginx.tf` runs and the placeholder will be replaced with the generated values*

- Create `tooling.sh` and insert the following:

```
#!/bin/bash
mkdir /var/www/
sudo mount -t efs -o tls,accesspoint="$1" "$2":/ /var/www/
yum install -y httpd 
systemctl start httpd
systemctl enable httpd
yum module reset php -y
yum module enable php:remi-7.4 -y
yum install -y php php-common php-mbstring php-opcache php-intl php-xml php-gd php-curl php-mysqlnd php-fpm php-json
systemctl start php-fpm
systemctl enable php-fpm
git clone https://github.com/Tonybesto/tooling.git
mkdir /var/www/html
cp -R /tooling/html/*  /var/www/html/
cd /tooling
mysql -h rcr-dbmysql.crvnhmpyxtuf.us-east-1.rds.amazonaws.com -u admin -p toolingdb < tooling-db.sql
cd /var/www/html/
touch healthstatus
sed -i "s/$db = mysqli_connect('172.31.32.49', 'webaccess', 'password', 'tooling');/$db = mysqli_connect('tcs-database.cgk2jcnauxqt.us-east-2.rds.amazonaws.com', 'TCSadmin', '1234567890', 'toolingdb');/g" functions.php
chcon -t httpd_sys_rw_content_t /var/www/html/ -R
systemctl restart httpd
```

*In the sudo mount line, $1 & $2 are used as placeholders for the EFS mount points and access points. The values will be gotten when the `provisioner` line in `asg-wordpress-nginx.tf` runs and the placeholder will be replaced with the generated values*

