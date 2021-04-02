REG ?= azssi
IMG ?= imagescan-api-server

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o main main.go

docker-image:
	docker build . -t "${REG}/${IMG}"

docker-push: docker-image
	docker push "${REG}/${IMG}"