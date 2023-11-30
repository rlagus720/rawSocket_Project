/*  C 언어로 작성된 패킷 캡처 프로그램입니다.
      - ICMP, DNS, HTTP, SSH 4종 프로토콜 전용입니다.
      - raw socket을 통해 Network Device로부터 패킷 or 데이터를 수신합니다.
      - 리눅스 운영체제를 기반으로 작동합니다.

    Network 트래픽을 감지하고 특정 프로토콜에 대한 세부 정보를 로그 파일에 저장하는 기능을 가지고 있습니다.
*/

// 헤더파일 정의
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// 캡쳐된 패킷을 저장하는데 사용되는 버퍼의 크기를 65536으로 정의
#define BUFFER_SIZE 65536

//전역변수 정의
FILE* logfile;                          // 캡쳐된 패킷 정보를 로그 파일에 쓰기 위한 파일 포인터
int sock_raw;                           // raw socket의 socket discriptor
struct sockaddr_in source, dest;        // 송신지와 수신지의 IP 주소를 저장하기 위한 구조체
int myflag = 0;

void ProcessPacket(unsigned char*, int, char*);     // 패킷을 처리하고 4종 프로토콜(ICMP, DNS, HTTP, SSH)에 맞는 함수를 호출하는 함수
void LogIcmpPacket(unsigned char*, int, char*);     // ICMP 패킷 세부 정보를 기록하는 함수
void LogDnsPacket(unsigned char*, int, char*);      // DNS 패킷 세부 정보를 기록하는 함수
void LogHttpPacket(unsigned char*, int, char*);     // HTTP 패킷 세부 정보를 기록하는 함수
void LogSshPacket(unsigned char*, int, char*);      // SSH 패킷 세부 정보를 기록하는 함수
void LogIpHeader(unsigned char*, int, char*);       // IP 헤더 세부 정보를 기록하는 함수
void LogData(unsigned char*, int);                  // 데이터 페이로드 세부 정보를 기록하는 함수



// 패킷을 처리하고 4종 프로토콜(ICMP, DNS, HTTP, SSH)에 맞는 함수를 호출하는 함수
void ProcessPacket(unsigned char* buffer, int size, char* pip_so)
{
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct tcphdr* tcph = NULL;
      
    switch (iph->protocol) {
    // ICMP는 1번 포트를 이용한다
    case 1:     
        LogIcmpPacket(buffer, size, pip_so);
        printf("ICMP Packet Captured\t");
        break;
    // TCP는 6번 포트를 이용한다
    case 6:
        // TCP를 사용하는 HTTP는 80번 포트를 이용한다
        tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iph->ihl * 4);
        if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80) {
            LogHttpPacket(buffer, size, pip_so);
            printf("HTTP Packet Captured\t");
        }
        // TCP를 사용하는 SSH Protocol은 22번 포트를 이용한다
        if (ntohs(tcph->source) == 22 || ntohs(tcph->dest) == 22) {
            LogSshPacket(buffer, size, pip_so);
            printf("SSH Packet Captured\t");
        }
        break;

    //DNS Protocol은 17번 포트를 이용한다
    case 17:
        if(myflag){
              LogDnsPacket(buffer, size, pip_so);
              printf("DNS Packet Captured\t");
        }
        break;
    }
}

// ICMP 패킷 세부 정보를 기록하는 함수
void LogIcmpPacket(unsigned char* buffer, int size, char* pip_so)
{
    // IP 헤더에서 ICMP 헤더로 이동
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    struct icmphdr* icmph = (struct icmphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

    // ICMP 패킷 헤더의 크기
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);

    // ICMP 패킷 분석 정보 로깅 시작
    fprintf(logfile, "\n\n- - - - - - - - - - - ICMP Packet - - - - - - - - - - - - \n");

    LogIpHeader(buffer, size, pip_so);

    fprintf(logfile, "\nICMP Header\n");
    fprintf(logfile, " + Type                 : %u\n", (unsigned int)(icmph->type));
    fprintf(logfile, " | Code                 : %u\n", (unsigned int)(icmph->code));
    fprintf(logfile, " | Checksum             : %d\n", ntohs(icmph->checksum));
    fprintf(logfile, " + Identifier           : %u\n", ntohs(icmph->un.echo.id));
    fprintf(logfile, " | Sequence Number      : %u\n", ntohs(icmph->un.echo.sequence));

    // IP 헤더 데이터 로깅
    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    LogData(buffer, iphdrlen);

    // ICMP 헤더 데이터 로깅 
    fprintf(logfile, "\nICMP Header\n");
    LogData(buffer + iphdrlen, sizeof(struct icmphdr));

    // ICMP 데이터 페이로드 로깅
    fprintf(logfile, "\nData Payload\n");
    LogData(buffer + header_size, size - header_size);

    // ICMP 패킷 로깅 종료
    fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - -");
}

// DNS Protocol 헤더 정보를 저장하는 구조체
struct dnshdr {
    uint16_t id;                // DNS Protocol 패킷 식별자 (Identification)
    uint16_t flags;             // DNS Flags - 여러가지 제어 정보를 담고 있음
    uint16_t questions;         // DNS 질의의 개수 
    uint16_t answer_rrs;        // DNS 응답 레코드의 개수
    uint16_t authority_rrs;     // DNS 권한 레코드의 개수
    uint16_t additional_rrs;    // DNS 추가 레코드의 개수
};

// DNS Protocol 패킷 세부 정보를 기록하는 함수
void LogDnsPacket(unsigned char* buffer, int size, char* pip_so)
{
    // IP 헤더 정보를 읽어옴
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    // UDP 헤더 정보를 읽어옴
    struct udphdr* udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

    // 헤더의 전체 크기 계산 (Ethernet 헤더 + IP 헤더 + UDP 헤더)
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);

    // DNS Protocol 패킷 로깅 시작
    fprintf(logfile, "\n\n- - - - - - - - - - - DNS Packet - - - - - - - - - - - - \n");

    // IP 헤더 정보 로깅
    LogIpHeader(buffer, size, pip_so);

    // UDP 헤더 정보 로깅
    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, " + Source Port          : %d\n", ntohs(udph->source));
    fprintf(logfile, " | Destination Port     : %d\n", ntohs(udph->dest));
    fprintf(logfile, " | UDP Length           : %d\n", ntohs(udph->len));
    fprintf(logfile, " + UDP Checksum         : %d\n", ntohs(udph->check));

    // DNS 헤더 정보 로깅
    fprintf(logfile, "\nDNS Header\n");
    struct dnshdr* dnsh = (struct dnshdr*)(buffer + header_size);
    fprintf(logfile, " + Transaction ID       : %d\n", ntohs(dnsh->id));
    fprintf(logfile, " | Flags                : %d\n", ntohs(dnsh->flags));
    fprintf(logfile, " | Questions            : %d\n", ntohs(dnsh->questions));
    fprintf(logfile, " | Answer RRs           : %d\n", ntohs(dnsh->answer_rrs));
    fprintf(logfile, " | Authority RRs        : %d\n", ntohs(dnsh->authority_rrs));
    fprintf(logfile, " + Additional RRs       : %d\n", ntohs(dnsh->additional_rrs));

    // DNS 데이터 페이로드 로깅
    fprintf(logfile, "\nData Payload\n");
    LogData(buffer + header_size + sizeof(struct dnshdr), size - header_size - sizeof(struct dnshdr));

    // DNS 패킷 로깅 종료
    fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - -");
}

// IP 헤더 세부 정보를 기록하는 함수
void LogIpHeader(unsigned char* buffer, int size, char* pip_so)
{
    unsigned short iphdrlen;

    // IP 헤더의 시작 위치를 계산
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    // 송신지 IP 주소 초기화 및 설정
    memset(&source, 0, sizeof(source));
    iph->saddr = inet_addr(pip_so);
    source.sin_addr.s_addr = iph->saddr;//ip를 받아온다.

    // 목적지 IP 주소 초기화 및 설정
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    // IP 헤더 정보 로깅
    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, " + IP Version          : %d\n", (unsigned int)iph->version);
    fprintf(logfile, " | IP Header Length    : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
    fprintf(logfile, " | Type Of Service     : %d\n", (unsigned int)iph->tos);
    fprintf(logfile, " | IP Total Length     : %d  Bytes (FULL SIZE)\n", ntohs(iph->tot_len));
    fprintf(logfile, " | TTL                 : %d\n", (unsigned int)iph->ttl);
    fprintf(logfile, " | Protocol            : %d\n", (unsigned int)iph->protocol);
    fprintf(logfile, " | Checksum            : %d\n", ntohs(iph->check));
    fprintf(logfile, " | Source IP           : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, " + Destination IP      : %s\n", inet_ntoa(dest.sin_addr));
}

// HTTP 패킷 헤더 정보를 기록하는 함수
void LogHttpPacket(unsigned char* buffer, int size, char* pip_so)
{
    // HTTP 패킷 로깅 시작
    fprintf(logfile, "\n\n- - - - - - - - - - - HTTP Packet - - - - - - - - - - - - \n");

    // Ethernet 헤더 정보 로깅
    struct ethhdr* eth = (struct ethhdr*)buffer;
    fprintf(logfile, "\nEthernet Header\n");
    fprintf(logfile, " + Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, " + Destination MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile, " + Protocol: %u\n", (unsigned short)eth->h_proto);

    LogIpHeader(buffer, size, pip_so);
    
    // TCP 헤더 정보 로깅
    struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    fprintf(logfile, "\nTCP Header\n");
    fprintf(logfile, " + Source Port: %u\n", ntohs(tcph->source));
    fprintf(logfile, " + Destination Port: %u\n", ntohs(tcph->dest));
    fprintf(logfile, " + Sequence Number: %u\n", ntohl(tcph->seq));
    fprintf(logfile, " + Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
    fprintf(logfile, " + Header Length: %d BYTES\n", (unsigned int)tcph->doff * 4);
    fprintf(logfile, " + Acknowledgement Flag: %d\n", (unsigned int)tcph->ack);
    fprintf(logfile, " + Finish Flag: %d\n", (unsigned int)tcph->fin);
    fprintf(logfile, " + Checksum: %d\n", ntohs(tcph->check));
    
    // HTTP 데이터 페이로드 로깅
    fprintf(logfile, "\nData Payload\n");
    LogData(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr), size - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr)));

    // HTTP 패킷 로깅 종료
    fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - -");
}

// SSH 패킷 헤더 정보를 기록하는 함수
void LogSshPacket(unsigned char* buffer, int size, char* pip_so)
{
    // SSH 패킷 로깅 시작
    fprintf(logfile, "\n\n- - - - - - - - - - - SSH Packet - - - - - - - - - - - - \n");

    // Ethernet 헤더 정보 로깅
    struct ethhdr* eth = (struct ethhdr*)buffer;
    fprintf(logfile, "\nEthernet Header\n");
    fprintf(logfile, " + Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, " + Destination MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile, " + Protocol: %u\n", (unsigned short)eth->h_proto);

    LogIpHeader(buffer, size, pip_so);

    // TCP 헤더 정보 로깅
    struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    fprintf(logfile, "\nTCP Header\n");
    fprintf(logfile, " + Source Port: %u\n", ntohs(tcph->source));
    fprintf(logfile, " + Destination Port: %u\n", ntohs(tcph->dest));
    fprintf(logfile, " + Sequence Number: %u\n", ntohl(tcph->seq));
    fprintf(logfile, " + Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
    fprintf(logfile, " + Header Length: %d BYTES\n", (unsigned int)tcph->doff * 4);
    fprintf(logfile, " + Acknowledgement Flag: %d\n", (unsigned int)tcph->ack);
    fprintf(logfile, " + Finish Flag: %d\n", (unsigned int)tcph->fin);
    fprintf(logfile, " + Checksum: %d\n", ntohs(tcph->check));

    // SSH 데이터 페이로드 로깅
    fprintf(logfile, "\nData Payload\n");
    LogData(buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr), size - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr)));

    // SSH 패킷 로깅 종료
    fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - -");
}

// 데이터 페이로드 세부 정보를 기록하는 함수
void LogData(unsigned char* buffer, int size)
{
    int i, j;
    for (i = 0; i < size; i++) { 
        // 데이터 페이로드는 한 줄에 16바이트씩 출력
        // 따라서 한 줄에 16바이트씩 출력되도록 설정
        if (i != 0 && i % 16 == 0) { 

            for (j = i - 16; j < i; j++) {
                if (buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(logfile, " %c", (unsigned char)buffer[j]);
                }
                else {
                    // 데이터 페이로드 바이트가 비어있으면 공백 처리
                    fprintf(logfile, " *");
                }
            }
            // 16바이트를 모두 출력한 이후 다음 줄로 이동
            fprintf(logfile, "\t\n");
        }

        if (i % 16 == 0) {
            fprintf(logfile, " ");
        }
        // 데이터 페이로드 양식에 맞게 2자리 16진수로 표현하여 바이트 코드 출력
        // 데이터의 가독성을 높이기 위해 넣은 코드
        fprintf(logfile, " %02X", (unsigned int)buffer[i]);

        if (i == size - 1) {
            for (j = 0; j < 15 - i % 16; j++) {
                // 가독성 높은 정렬된 출력을 생성하기 위해 여백 추가
                fprintf(logfile, "  "); 
            }

            // 마지막 줄의 문자 출력
            for (j = i - i % 16; j <= i; j++) {
                if (buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(logfile, " %c", (unsigned char)buffer[j]);
                }
                else {
                    fprintf(logfile, " *");
                }
            }

            fprintf(logfile, "\n");
        }
    }
}

int main(int argc, char* argv[])
{
    char ip_source[18];
    char* pip_so = ip_source;
    char num_port[7];
    char* p_port = num_port;

    printf("+------ Packet Capture Program -------+\n");

    strcpy(p_port, argv[1]);
    printf("| Entered port:   %s\n", p_port);

    strcpy(pip_so, argv[2]);
    printf("| Entered ip:   %s\n", pip_so);

    printf("+--------------------------------+\n");

    socklen_t saddr_size;
    int data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);

    // 사용자가 선택한 Protocol에 기반하여 로그 파일을 열고 패킷 정보를 작성
    if (!strcmp(p_port, "icmp")) {
        logfile = fopen("log_icmp.txt", "w");
        printf("log_icmp.txt Writing\n");
        if (logfile == NULL) {
            printf("icmp log file create failed\n");
            return 1;
        }
    }

    else if (!strcmp(p_port, "dns")) {
        myflag = 1;
        logfile = fopen("log_dns.txt", "w");
        printf("log_dns.txt Writing\n");
        if (logfile == NULL) {
            printf("dns log file create failed \n");
            return 1;
        }
    }
    else if (!strcmp(p_port, "http")) {
        logfile = fopen("log_http.txt", "w");
        printf("log_http.txt Writing\n");
        if (logfile == NULL) {
            printf("http log file create failed \n");
            return 1;
        }
    }
    else if (!strcmp(p_port, "ssh")) {
        logfile = fopen("log_ssh.txt", "w");
        printf("log_ssh.txt Writing\n");
        if (logfile == NULL) {
            printf("ssh log file create failed \n");
            return 1;
        }
    }
    
    else {
        printf("Unknown Error \n");
        return 1;
    }
    // AF_PACKET, SOCK_RAW 를 사용하여 소켓 초기화 (Layer 2까지 조작 가능)
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        printf("socket init failed\n");
        return 1;
    }

    while (1) {
        saddr_size = sizeof saddr;

        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
        if (data_size < 0) {
            printf("return is smaller than 0");
            return 1;
        }

        ProcessPacket(buffer, data_size, pip_so);
    }

    close(sock_raw);

    return 0;
}
