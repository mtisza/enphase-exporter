#########################################################
# build the app in docker, and create a container
#########################################################
DOCKER_REPO ?= docker.io
DOCKER_IMAGE ?= mtisza/enphase-exporter
GIT_HASH ?= $(shell git log --format="%h" -n 1)

ifeq ("${V}","1")
DOCKER_VERBOSE := --progress=plain
endif

# using regctl from https://github.com/regclient/regclient/releases/download/v0.7.1/regctl-linux-amd64
# should be installed in the PATH of the build host

build:
	docker build \
		${DOCKER_VERBOSE} \
		--tag ${DOCKER_REPO}/${DOCKER_IMAGE}:${GIT_HASH} \
		.

push:
	docker push ${DOCKER_REPO}/${DOCKER_IMAGE}:${GIT_HASH}

release:
	docker pull ${DOCKER_REPO}/${DOCKER_IMAGE}:${GIT_HASH}
	docker tag  ${DOCKER_REPO}/${DOCKER_IMAGE}:${GIT_HASH} ${DOCKER_REPO}/${DOCKER_IMAGE}:latest
	docker push ${DOCKER_REPO}/${DOCKER_IMAGE}:latest

build-dev:
	docker build \
		${DOCKER_VERBOSE} \
		--tag ${DOCKER_IMAGE}:dev \
		.

run:
	docker run --rm \
		--env-file .env \
		-p 8080:8080 \
		${DOCKER_IMAGE}:dev
