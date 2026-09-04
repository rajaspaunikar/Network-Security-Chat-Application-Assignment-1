Run test using these commands 
test

g++ -std=c++17 -Wall dh.cpp test_dh.cpp -o test -lcrypto

server

g++ -std=c++17 -Wall -pthread dh.cpp server.cpp -o server -lcrypto

client

g++ -std=c++17 -Wall -pthread dh.cpp client.cpp -o client -lcrypto