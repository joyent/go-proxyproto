BIN=./subtlv.test

all:
	go test -v -run TestSubTlv
#	go build
#	sudo ${BIN}

run:
	sudo ${BIN}

clean:
	rm -f ${BIN}

