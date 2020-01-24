.PHONY: test

test: build
	npm test

build: node_modules
	npm build

node_modules: package.json
