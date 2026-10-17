FROM debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931

RUN apt-get update \
    && apt-get install --no-install-recommends -y libguestfs-tools linux-image-arm64 \
    && rm -rf /var/lib/apt/lists/*

ENV LIBGUESTFS_BACKEND=direct \
    LIBGUESTFS_BACKEND_SETTINGS=force_tcg

ENTRYPOINT ["guestfish"]
