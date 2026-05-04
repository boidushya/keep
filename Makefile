.PHONY: build run test vet css clean

build:
	@./scripts/build.sh

run: build
	@./keep

test:
	@go test ./... -race

vet:
	@go vet ./...

css:
	@cd web && npx tailwindcss -i ./input.css -o ./dist/keep.css --minify

clean:
	@rm -f keep web/dist/keep.css
