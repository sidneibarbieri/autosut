
# Attacker container - attack tools
FROM ubuntu:20.04

# Install attack tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    nmap \
    openssh-client \
    git \
    vim \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install requests paramiko beautifulsoup4

# Create directories
RUN mkdir -p /tmp/staging /tmp/artifacts /root/.ssh

# Create SSH keys
RUN ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa

# Set working directory
WORKDIR /workspace

CMD tail -f /dev/null
