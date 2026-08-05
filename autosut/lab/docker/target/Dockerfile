
# Target container - vulnerable system
FROM ubuntu:20.04

# Install required packages
RUN apt-get update && apt-get install -y \
    apache2 \
    php7.4 \
    python3 \
    python3-pip \
    openssh-server \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Configure Apache
RUN a2enmod php7.4 rewrite && systemctl enable apache2

# Create vulnerable web application
RUN echo '<?php if(isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>' > /var/www/html/vulnerable.php

# Create staging directory
RUN mkdir -p /tmp/staging && chmod 777 /tmp/staging

# Create user accounts
RUN useradd -m -s /bin/bash labuser && echo "labuser:weakpass123" | chpasswd

# Create sensitive files
RUN echo "sensitive_data_$(date)" > /home/labuser/secrets.txt

# Expose ports
EXPOSE 80 22

# Start services
CMD service apache2 start && service ssh start && tail -f /dev/null
