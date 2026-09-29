# IAC-FP-001: localhost-only rule. If a scanner reports public exposure,
# classify it as a false positive after reviewing the effective CIDR.
resource "aws_security_group" "localhost_service" {
  name = "aspm-lab-localhost-only"

  ingress {
    description = "Local laboratory service only"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["127.0.0.1/32"]
  }
}

