REG ?= azssi
IMG ?= imagescan-api

build:
	@echo "Build binary"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o build/imagescan-api-server main.go

docker-image:
	@echo "Build docker image \"${REG}/${IMG}\""
	docker build . -t "${REG}/${IMG}"

docker-push: docker-image
	@echo "Push docker image \"${REG}/${IMG}\""
	docker push "${REG}/${IMG}"