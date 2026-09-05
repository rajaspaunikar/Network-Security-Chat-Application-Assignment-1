CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lcrypto

COMMON_SRCS = cert.cpp crypto/crypto.cpp dh/dh.cpp

TARGETS = server client test_cert fake_server

.PHONY: all clean certs

all: $(TARGETS)

server: server.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) -pthread $^ -o $@ $(LDFLAGS)

client: client.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) -pthread $^ -o $@ $(LDFLAGS)

test_cert: test_cert.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

fake_server: fake_server.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

certs: ca_cert.pem server_cert.pem

ca_cert.pem server_cert.pem:
	./setup_ca.sh

clean:
	rm -f $(TARGETS)