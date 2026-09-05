CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lcrypto

COMMON_SRCS = cert.cpp crypto/crypto.cpp dh/dh.cpp

TARGETS = server client test_cert fake_server test_pop fake_server_stolen_cert mitm_proxy

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

test_pop: test_pop.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

fake_server_stolen_cert: fake_server_stolen_cert.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

mitm_proxy: mitm_proxy.cpp $(COMMON_SRCS)
	$(CXX) $(CXXFLAGS) -pthread $^ -o $@ $(LDFLAGS)

certs: ca_cert.pem server_cert.pem

ca_cert.pem server_cert.pem:
	./setup_ca.sh

clean:
	rm -f $(TARGETS)