.PHONY: test
test:
	go test -tags=testharness -v ./...

.PHONY: cover
cover:
	go test -tags=testharness -coverprofile=bin/cover.out ./pkcs11
	go tool cover -html=bin/cover.out
