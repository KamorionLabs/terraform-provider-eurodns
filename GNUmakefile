default: build

build:
	go build ./...

lint:
	gofmt -l . | (! grep .)
	go vet ./...

# Unit and acceptance tests run against in-memory fakes of EuroDNS and
# dns-gate: no credentials and no network access to EuroDNS are needed.
test:
	go test -count=1 ./...

test-tofu:
	TF_ACC_TERRAFORM_PATH=$$(command -v tofu) TF_ACC_PROVIDER_HOST=registry.opentofu.org go test -count=1 ./...

docs:
	go generate ./...

install:
	go install .

.PHONY: default build lint test test-tofu docs install
