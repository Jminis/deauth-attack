LDLIBS += -ltins -lpcap

all: deauth-attack

deauth-attack2.cpp: deauth-attack.cpp

clean:
	rm -f deauth-attack *.o
