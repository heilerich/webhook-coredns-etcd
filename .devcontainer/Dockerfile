# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.217.4/containers/go/.devcontainer/base.Dockerfile

# [Choice] Go version (use -bullseye variants on local arm64/Apple Silicon): 1, 1.16, 1.17, 1-bullseye, 1.16-bullseye, 1.17-bullseye, 1-buster, 1.16-buster, 1.17-buster
ARG VARIANT="1.17-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/go:0-${VARIANT}

# [Choice] Node.js version: none, lts/*, 16, 14, 12, 10
ARG NODE_VERSION="none"
RUN if [ "${NODE_VERSION}" != "none" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

ARG USER_UID=1000

RUN usermod --uid $USER_UID vscode \
    && chown -R $USER_UID:1000 /home/vscode

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends dnsutils \
    && rm -fr /var/lib/apt/lists/*

ARG KUBE_VERSION=1.22.1
ARG OS=linux
ARG ARCH=amd64
RUN curl -fSL https://go.kubebuilder.io/test-tools/$KUBE_VERSION/$OS/$ARCH -o kubebuilder-tools.tar.gz \
    && mkdir -p /kubebuilder \
    && tar -xvf kubebuilder-tools.tar.gz \
    && mv kubebuilder/bin /kubebuilder/ \
    && rm kubebuilder-tools.tar.gz \
    && rm -rf kubebuilder

ENV TEST_ASSET_ETCD=/kubebuilder/bin/etcd
ENV TEST_ASSET_KUBE_APISERVER=/kubebuilder/bin/kube-apiserver
ENV TEST_ASSET_KUBECTL=/kubebuilder/bin/kubectl

USER vscode

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1
