.PHONY: clean

build/passman: build/rsa.o build/main.o
	g++ $^ -o $@ -lssl -lcrypto

build/rsa.o: src/rsa.cpp include/rsa.h
	mkdir -p build
	g++ $< -Iinclude -c -o $@

build/main.o: src/main.cpp
	mkdir -p build
	g++ $< -Iinclude -c -o build/main.o

clean:
	rm -rf build
