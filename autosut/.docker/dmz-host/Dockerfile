FROM alpine:3.19
# Bake all attacker-side tools into the image so campaign replay does not
# install packages during every run. This is a build-time one-shot.
RUN apk add --no-cache \
    bash \
    curl \
    mariadb-client \
    netcat-openbsd \
    openssh \
    openssl \
    py3-requests \
    python3 \
    shadow \
    socat \
    sshpass
RUN ssh-keygen -A
RUN mkdir -p /root/.ssh && \
    printf 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n' > /root/.ssh/config && \
    chmod 600 /root/.ssh/config
