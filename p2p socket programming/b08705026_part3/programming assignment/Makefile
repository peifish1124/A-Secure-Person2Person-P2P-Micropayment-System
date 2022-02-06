
output: server.o client.o
	g++ server.o -o server -pthread -lssl -lcrypto
	g++ client.o -o client -pthread -lssl -lcrypto

server.o: server.cpp
	g++ -c server.cpp -lssl -lcrypto

client.o: client.cpp
	g++ -c client.cpp -lssl -lcrypto


clean:
	rm *.o server
	rm *.o client
