.PHONY:all
all: build-linux build-mac build-windows

.PHONY:build-windows
build-windows: 
	env GOOS=windows GOARCH=amd64 go build -o hashchecker.exe .

.PHONY:build-linux
build-linux:
	env GOOS=linux GOARCH=amd64 go build -o hashchecker_linux .

.PHONY:build-mac
build-mac:
	env GOOS=darwin GOARCH=amd64 go build -o hashchecker_mac .