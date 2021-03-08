cert:
	openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout key.pem -out cert.pem -subj "/CN=kibana" -days 3650

deployment.yaml:
	kubectl kustomize . > deployment.yaml

deploy: deployment.yaml
	kubectl create -f deployment.yaml

clean:
	kubectl delete -f deployment.yaml
	rm -rf deployment.yaml