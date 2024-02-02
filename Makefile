# up: run docker-compose up -d
up:
	docker-compose build
	docker-compose up -d

# down: destroy the docker files
down:
	docker-compose down

# bin: build the server  and output to .bin dir
bin:
	cd cmd && go build -o ../.bin/server

# run: runs the binary localy linux
run:
	chmod +x .bin/server
	./.bin/server
