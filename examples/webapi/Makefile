
apigw := localhost
port := 80
ssl_port := 443
pp_port := 8080
pp_ssl_port := 8443

-include Makefile.local

build:
	go build -o webapi

server:
	sudo pkill webapi || true
	sudo ./webapi -mode=server

curl:
	@echo  "### print http header"
	curl ${apigw}:${port}/headers
	curl ${apigw}:${port}/hello

curl_ssl:
	@echo  "### print http header"
#   curl -v --insecure https://localhost:${ssl_port}/headers
	curl --insecure https://${apigw}:${ssl_port}/hello
	curl --insecure https://${apigw}:${ssl_port}/headers

client:
	./webapi -mode=client             -url="http://${apigw}:${port}/headers"

pp:
	./webapi -mode=client -ppv=2      -url="http://${apigw}:${pp_port}/headers"

client_all:
#	./webapi -mode=client -url="http://${apigw}:${port}/hello"
#	./webapi -mode=client -ssl -url="https://${apigw}:${ssl_port}/hello"

	./webapi -mode=client             -url="http://${apigw}:${port}/headers"
#	./webapi -mode=client -ssl        -url="https://${apigw}:${ssl_port}/headers"
#	./webapi -mode=client -ppv=1      -url="http://${apigw}:${pp_port}/headers"
#	./webapi -mode=client -ppv=1 -ssl -url="https://${apigw}:${pp_ssl_port}/headers"
#	./webapi -mode=client -ppv=2      -url="http://${apigw}:${pp_port}/headers"
#	./webapi -mode=client -ppv=2 -ssl -url="https://${apigw}:${pp_ssl_port}/headers"

key1:
	openssl req  -new  -newkey rsa:2048  -nodes  -keyout server.key  -out server.csr
	openssl  x509  -req  -days 365  -in server.csr  -signkey server.key  -out server.crt

key:
	openssl genrsa -out server.key 2048
	openssl ecparam -genkey -name secp384r1 -out server.key
	openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650

sign:
	openssl genrsa -out ca.key 2048
	openssl req -new -x509 -days 365 -key ca.key -subj "/C=IN/ST=KA/L=BL/O=MyOrg, Inc./CN=MyOrg Root CA" -out ca.crt
	openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/C=IN/ST=KA/L=BL/O=MyOrg, Inc./CN=localhost" -out server.csr
	openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

client_key:
	openssl req \
		-x509 \
		-nodes \
		-newkey rsa:2048 \
		-keyout client.key \
		-out client.crt \
		-days 3650 \
		-subj "/C=GB/ST=Seoul/L=Seoul/O=Global Security/OU=IT Department/CN=*"

server_key:
	openssl req \
    -newkey rsa:2048 \
    -nodes \
    -days 3650 \
    -x509 \
    -keyout ca.key \
    -out ca.crt \
    -subj "/CN=*"

	openssl req \
		-newkey rsa:2048 \
		-nodes \
		-keyout server.key \
		-out server.csr \
		-subj "/C=GB/ST=Seoul/L=Seoul/O=Global Security/OU=IT Department/CN=*"

	openssl x509 \
		-req \
		-days 365 \
		-sha256 \
		-in server.csr \
		-CA ca.crt \
		-CAkey ca.key \
		-CAcreateserial \
		-out server.crt \
		-extfile extfile.cnf


