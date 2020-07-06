SIM?=
PK=../DonkyLib
ARCH=x86_64
CXXFLAGS=-std=c++11 -I$(PK) -I$(PK)/pk -I$(PK)/pk/arch/$(ARCH) -g
export LD_LIBRARY_PATH=$(abspath $(PK))

PKARGS=PLATFORM=$(ARCH) SIM=$(SIM) SHARED=1 PRELOAD=1 RELEASE=1

all: main

$(PK)/libpku.so:
	make -C $(PK) $(PKARGS) libpku.so

$(PK)/libpk.so:
	make -C $(PK) $(PKARGS) libpk.so

main.o: main.cc
	$(CXX) $(CXXFLAGS) -c $^ -o $@

main: main.o tinyxml2.o | $(PK)/libpku.so
	$(CXX) -o $@ $(CXXFLAGS) $^ -L$(PK) -lpku -lpk -lpthread

tinyxml2.o: tinyxml2.cpp
	$(CXX) -c -o $@ $(CXXFLAGS) $^

clean:
	make -C $(PK) $(PKARGS) clean
	rm -f main main.o tinyxml2.o

run: main
	LD_LIBRARY_PATH=$(abspath $(PK)) ./main
