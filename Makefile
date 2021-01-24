# go options
GO              ?= go
LDFLAGS         :=
GOFLAGS         :=
BINDIR          := $(CURDIR)/bin
GO_FILES        := $(shell find . -type d -name '.cache' -prune -o -type f -name '*.go' -print)
GOPATH          ?= $$(go env GOPATH)
DOCKER_CACHE    := $(CURDIR)/.cache

all: build docker-image

build:
	$(GO) build ./...

test:
	$(GO) test -v -timeout 20m ./...


DOCKER_ENV := \
	@docker run --rm -u $$(id -u):$$(id -g) \
		-e "GOCACHE=/tmp/gocache" \
		-e "GOPATH=/tmp/gopath" \
		-w /usr/src/github.com/smartxworks/ofnet \
		-v $(DOCKER_CACHE)/gopath:/tmp/gopath \
		-v $(DOCKER_CACHE)/gocache:/tmp/gocache \
		-v $(CURDIR):/usr/src/github.com/smartxworks/ofnet \
		ofnet/build

$(DOCKER_CACHE):
	@mkdir -p $@/gopath
	@mkdir -p $@/gocache

docker-image:
	@docker build -q -f build/images/Dockerfile.build.ubuntu -t ofnet/build .

docker-build: $(DOCKER_CACHE) docker-image
	$(DOCKER_ENV) make build

docker-test: $(DOCKER_CACHE) docker-image
	docker-compose \
		-f deploy/docker-compose/docker-compose.ovs.yaml \
		-f deploy/docker-compose/docker-compose.test.yaml \
		up --build --remove-orphans --abort-on-container-exit --exit-code-from test
