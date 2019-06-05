APP=catscan
IMAGE=catscan
DOCKER_ROOT?=andrewstuart
NAMESPACE=catscan

FQTAG=$(DOCKER_ROOT)/$(IMAGE)

SHA=$(shell docker inspect --format "{{ index .RepoDigests 0 }}" $(1))

test:
	go test ./...

build:
	GOOS=linux go build -o app

docker: test build
	docker build -t $(FQTAG) . 
	docker push $(FQTAG)

deploy: docker
	kubectl apply -f k8s.yaml
	kubectl --namespace $(NAMESPACE) set image deployment/$(APP) $(APP)=$(call SHA,$(FQTAG))
