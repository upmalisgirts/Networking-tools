#include <iostream>
#include <iomanip>
#include <vector>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define SERVER_IP "8.8.8.8"
#define A 0x01
#define NS 0x02
#define MD 0x03
#define MF 0x04
#define CNAME 0x05


using namespace std;

void form_dns_query(char* address);
void form_dns_query_vector(char* address, vector<unsigned char> *pv);
const char * get_type(uint8_t type);

int main(int argc, char** argv) {
	srand(time(NULL));
	if (argc != 2) {
		cout << "Ivalid argument count: " << argc << endl;
		return -1;
	}
	
	vector<unsigned char> v(strlen(argv[1]) + 18,0), *pv;
	pv = &v;
	form_dns_query_vector(argv[1],pv);

	int sock = 0,valread;
	struct sockaddr_in my_addr;
	struct sockaddr_in dst_addr;
	
	
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        cout << "\n Socket creation error \n";
        return -1;
    }
    memset((char *) &dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(53);
    dst_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

	if (sendto(sock, (const unsigned char*)v.data(), v.size(), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
		cout << "Cannot send" << endl;
		return -1;
	}
	uint8_t buf[1500];
	socklen_t len;
	int blen = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*) &dst_addr, &len);

	if (blen == -1) {
		cout << "error";
		exit(0);
	}
	if ((buf[3] & 0x0F) | 0 << 3) {
		cout << "Error code: " << (int)(buf[3] & 0x0F) << endl;
		return -1;
	}
	int ans_count = (int)(buf[6] << 8 | buf[7]);
	cout << "Answer RRs: " << dec << ans_count << endl;
	cout << "Authority RRs: " << dec << (int)(buf[8] << 8 | buf[9]) << endl;
	cout << "Additional RRs: " << dec << (int)(buf[10] << 8 | buf[11]) << endl;
	cout << "-----" << endl;
	cout << "Answers:" << endl;

	int byte = v.size()+1;
	for (int ans = 0; ans < ans_count; ans++) {
		int name_pointer = byte;
		int name_pointer_val = (int)buf[name_pointer]+1;
		byte = byte+2;
		cout << "Name: ";
		while(buf[name_pointer_val] != 0x00) {
			if (buf[name_pointer_val] < 0x2D) {
				cout << ".";
			} else if (buf[name_pointer_val] == 0xC0) {
				name_pointer_val = (int)buf[name_pointer_val+1];
				continue;
			} else {
				cout << buf[name_pointer_val];
			}
			name_pointer_val++;
		}
		cout << endl;
		uint8_t type = buf[byte];
		cout << "Type: " << get_type(type) << endl;
		byte = byte+3;
		cout << "TTL: " << (int)((buf[byte++] << 24 | buf[byte++] << 16 | buf[byte++] << 8 | buf[byte++])) << " seconds" << endl;
		int data_len = (int)(buf[byte++] << 8 | buf[byte++]);
		cout << "Data length: " << data_len << endl;
		if (type == CNAME) {
			for (int i = 1; i < data_len; i++) {
				if (buf[byte+i] < 0x2D) {
					cout << ".";
				} else if (buf[byte+i] == 0xC0) {
					byte = byte+i+1;
					int suffix = (int)buf[byte];
					while (buf[suffix] != 0x00) {
						if (buf[suffix] < 0x2D) {
							cout << ".";
						} else {
							cout << buf[suffix];
						}
						suffix++;
					}
					byte = byte + data_len - i;
					break;
				} else {
					cout << buf[byte+i];
				}
			}
		} else if (type == A) {
			for (int i = 0; i < data_len; i++) {
				cout << (int)buf[byte+i];
				if (i != data_len - 1) {cout << ".";}
			}
			byte = byte + data_len + 1;
		}
		cout << endl << "-----------------" << endl;
	}
	return 0;
}

void form_dns_query(char* address) {
	unsigned char size = 0;
	unsigned char partlen = 0;
	unsigned char buffer[100];
	while (*(address+size) != '\0') {
		if (*(address+size) != '.') {
			cout << *(address+size) << endl;
			buffer[size+1] = *(address+size);
			partlen++;
		} else {
			buffer[size - partlen] = partlen;
			cout << "Previous part length: " << (int)partlen << endl;
			partlen = 0;
		}
		size++;
	}
	buffer[size-partlen] = partlen;
	buffer[size+1] = 0x00;
	size = size + 2;

	unsigned char packet[16+size] {0};
	cout << (rand()&0xFF) << endl;
	packet[0] = (unsigned char)(rand()&0xFF);
	packet[1] = (unsigned char)(rand()&0xFF);
	packet[2] = 0x01;
	packet[5] = 0x01;
	for (size_t i = 0; i < size; i++) {
		packet[12 + i] = buffer[i];
	}
	packet[12 + size + 1] = 0x01;
	packet[12 + size + 3] = 0x01;
	cout << "-------------" << endl;
	for (auto i: packet) {
		cout << (int)i << endl;
	}
	cout << "----------" << endl;
	cout << setfill('0');

	for (auto i: packet) {
		cout << setw(2) << hex << (int)i << ' ';
	}

}

void form_dns_query_vector(char* address, vector<unsigned char> *pv) {
	size_t len = (*pv).size();
	(*pv)[0] = (unsigned char)(rand()&0xFF);
	(*pv)[1] = (unsigned char)(rand()&0xFF);
	(*pv)[2] = 0x01;
	(*pv)[5] = 0x01;
    (*pv)[len-1] = 0x01;
    (*pv)[len-3] = 0x01;
	unsigned char size = 0;
	unsigned char partlen = 0;
	cout << "Requested domain name: ";
	while (address[size] != '\0') {
		cout << address[size];
		if (address[size] != '.') {
            (*pv)[size+12+1] = address[size];
			partlen++;
		} else {
            (*pv)[size+12-partlen] = partlen;
			partlen = 0;
		}
		size++;
	}
    (*pv)[size+12-partlen] = partlen;
	cout << endl << "----------" << endl;
}

const char * get_type(uint8_t type) {
	switch(type) {
		case A:
			return "A";
		case NS:
			return "NS";
		case MD:
			return "MD";
		case MF:
			return "MF";
		case CNAME:
			return "CNAME";
	}
	return "ERROR";
}
