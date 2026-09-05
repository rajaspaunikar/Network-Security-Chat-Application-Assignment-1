CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lcrypto

COMMON_SRCS = cert.cpp crypto/crypto.cpp dh/dh.cpp

TARGETS = server client

.PHONY: all clean certs

all: $(TARGETS)

server: server.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) -pthread $^ -o $@ $(LDFLAGS)

client: client.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) -pthread $^ -o $@ $(LDFLAGS)

certs: ca_cert.pem server_cert.pem

ca_cert.pem server_cert.pem:
	./setup_ca.sh

clean:
	rm -f $(TARGETS)