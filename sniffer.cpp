#include "sniffer.h"
#include <iostream>
#include <netinet/if_ether.h> // to be able to use the structure struct ethhdr{};
#include <netinet/ip.h> // to be able to use the structure struct iphdr{};
#include <netinet/tcp.h> // to be able to use the structure struct tcphdr{};
#include <netinet/udp.h> // to be able to use the structure struct udphdr{};
#include <arpa/inet.h> // to be able to use the functioin inet_ntoa();
#include <cstring> // to be able to use the function memeset();
#include <fstream> // to be able to write to a file
#include <string> 
#include <netinet/ip_icmp.h> // to be able to use the structure struct icmp{};
#include <linux/igmp.h> // to be able to use the structure struct igmp{};
#include <netinet/in.h> // to be able to use the structure struct sockaddr_in{};
#include <csignal> // CTR+C


#define ERROR_FILE "Error opening file\n"
#define BUFFER_SIZE 65536

using std::cout;
using std::endl;

int tcp, udp, icmp, igmp, others, total, iphdrlen;
unsigned int total_size_packet;

struct sockaddr_in source, dest;
struct sockaddr saddr;

std::string file = "report.txt";
std::ofstream fout(file, std::ios_base::out | std::ios_base::trunc);

void start_sniffing(int sock)
{
	unsigned char *buffer = new unsigned char[BUFFER_SIZE];
	int result;
	
	if(buffer == nullptr)
	{
		cout << "Failed to allocate a memory on a heap.\n";
		return;
	}

	do
	{
		result = recv(sock, buffer, BUFFER_SIZE, 0);
		if(result > 0)
			process_packet(buffer, result);
		else
			cout << "recv() failed.\n";
	}while(result > 0);
	
	delete[]buffer;
}

void process_packet(unsigned char *buffer, int size)
{
	struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	++total;

	switch(ip->protocol)
	{
		case 1: // ICMP Protocol
			++icmp;
			print_icmp_packet(buffer, size);
			break;

		case 2: // IGMP Protocol
			++igmp;
			print_igmp_packet(buffer, size);
			break;

		case 6: // TCP Protocol
			++tcp;
			print_tcp_packet(buffer, size);
			break;

		case 17: // UDP Protocol
			++udp;
			print_udp_packet(buffer, size);
			break;
		
		default: // Other Protocol
			++others;
			break;
	}
}

void print_ethernet_packet(unsigned char *buffer)
{
	struct ethhdr *ether = (struct ethhdr *)(buffer);

	if(!fout.is_open())
		cout << ERROR_FILE;
	else
	{
		fout << "\nEthernet Header\n";
		fout << "\t|-Source Address: ";
	        std::hex(fout);
		fout.width(12);
		fout << (int)ether->h_source[0] << "-" << (int)ether->h_source[1] << "-" << (int)ether->h_source[2] << "-"
			<< (int)ether->h_source[3] << "-" << (int)ether->h_source[4] << "-" << (int)ether->h_source[5] << endl; // mac-address
		fout << "\t|-Destination:";
	        std::hex(fout);
		fout.width(16);
		fout << (int)ether->h_dest[0] << "-" << (int)ether->h_dest[1] << "-" << (int)ether->h_dest[2] << "-" 
		       << (int)ether->h_dest[3] << "-" << (int)ether->h_dest[4] << "-" << (int)ether->h_dest[5] << endl; // mac-address 
		fout << "\t|-Protocol:";
	        fout.width(18);
		fout << ether->h_proto << endl;
	}	
}

void print_ip_packet(unsigned char *buffer)
{
	struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	iphdrlen = ip->ihl * 4;

	memset(&source, 0, sizeof(source)); // returns a pointer to a memory block
	source.sin_addr.s_addr = ip->saddr; // saddr - field structure iphdr

	memset(&dest, 0, sizeof(dest)); // returns a pointer to a memory block
	dest.sin_addr.s_addr = ip->daddr; // daddr - field structure iphdr

	if(!fout.is_open())
		cout << ERROR_FILE;
	else
	{
		std::dec(fout);
		fout << "\nIP Header\n";
		fout << "\t|-IP Version:\t\t\t\t" << ip->version << endl;
		fout << "\t|-IP Header Lenght:\t\t\t" << (unsigned int)ip->ihl << " dwords, " << (unsigned int)ip->ihl * 4 << " bytes\n";
		fout << "\t|-Type Of Service:\t\t\t" << (unsigned int)ip->tos << endl;
		fout << "\t|-IP Total Length:\t\t\t" << ntohs(ip->tot_len) << " bytes(sizeof packet)\n";
		total_size_packet += (unsigned int) ntohs(ip->tot_len);
		fout << "\t|-Identification:\t\t\t" << ntohs(ip->id) << endl;
		fout << "\t|-Time To Live:\t\t\t\t" << (unsigned int)ip->ttl << endl;
		fout << "\t|-Protocol:\t\t\t\t\t" << (unsigned int)ip->protocol << endl;
		fout << "\t|-Header Checksum:\t\t\t" << ntohs(ip->check) << endl;
		fout << "\t|-Source IP:\t\t\t\t" << inet_ntoa(source.sin_addr) << endl;
		fout << "\t|-Destination IP:\t\t\t" << inet_ntoa(dest.sin_addr) << endl;
	}
}

void print_tcp_packet(unsigned char *buffer, int size)
{
	if(!fout.is_open())
		cout << ERROR_FILE;
	else
	{
		fout << "\n\n==============================TCP PACKET=============================\n";
		print_ethernet_packet(buffer);
		print_ip_packet(buffer);

		struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

		fout << "\nTCP Header\n";
		fout << "\t|- Source Port:\t\t\t\t" << ntohs(tcp->source) << endl;
		fout << "\t|- Destination Port:\t\t" << ntohs(tcp->dest) << endl;
		fout << "\t|- Sequence Number:\t\t\t" << ntohl(tcp->seq) << endl;
		fout << "\t|- Acknowledge Number:\t\t" << ntohl(tcp->ack_seq) << endl;
		fout << "\t|- Header Length:\t\t\t" << (unsigned int)tcp->doff << " dwords, "
		       << (unsigned int)tcp->doff * 4 << " bytes\n";
		fout << "\t--------------Flags-------------\n";
		fout << "\t\t|- Urgent flags:\t\t\t" << (unsigned int)tcp->urg << endl;
		fout << "\t\t|- Acknowledgement flag:\t" << (unsigned int)tcp->ack <<endl;
		fout << "\t\t|- Push flag:\t\t\t\t" << (unsigned int)tcp->psh << endl;
		fout << "\t\t|- Reset flag:\t\t\t\t" << (unsigned int)tcp->rst << endl;
		fout << "\t\t|- Synchronise flag:\t\t" << (unsigned int)tcp->syn << endl;
		fout << "\t\t|- Finish flag:\t\t\t\t" << (unsigned int)tcp->fin << endl;
		fout << "\t|- Window:\t\t\t\t\t" << ntohs(tcp->window) << endl;
		fout << "\t|- Checksum:\t\t\t\t" << ntohs(tcp->check) << endl;
		fout << "\t|- Urgent pointer:\t\t\t" << tcp->urg_ptr << endl;
		
		print_data(buffer, size);

		fout << "\n*********************************************************************\n";
	}	
}	

void print_udp_packet(unsigned char *buffer, int size)
{
	if(!fout.is_open())
		cout << ERROR_FILE;
	else
	{
		fout << "\n\n==============================UDP PACKET=============================\n";
		print_ethernet_packet(buffer);
		print_ip_packet(buffer);

		fout << "\nUDP Header\n";

		struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
		
		fout << "\t|- Source port:\t\t\t\t" << ntohs(udp->source) << endl;
		fout << "\t|- Destination port:\t\t" << ntohs(udp->dest) << endl;
		fout << "\t|- UDP length:\t\t\t\t" << ntohs(udp->len) << endl;
		fout << "\t|- UDP checksum:\t\t\t" << ntohs(udp->check) << endl;

		print_data(buffer, size);

		fout << "\n*********************************************************************\n";
	}
}

void print_icmp_packet(unsigned char *buffer, int size)
{
	if(!fout.is_open())
		cout << ERROR_FILE;
	else
	{
		fout << "\n\n==============================icmp packet=============================\n";
		print_ethernet_packet(buffer);
		print_ip_packet(buffer);

		fout << "\nICMP Header\n";
		struct icmphdr *icmp = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
		fout << "\t|- Type: " << (unsigned int)(icmp->type) << endl;

		if((unsigned int)(icmp->type) == 5)
			fout << "\t|- TTL expired\n";
		else
			fout << "\tICMP echo reply\n";
		fout << "\t|- Code:\t\t\t\t\t\t" << (unsigned int)(icmp->code) << endl;
		fout << "\t|- Checksum:\t\t\t\t" << ntohs(icmp->checksum) << endl;
		fout << "\t|- ID:\t\t\t\t\t\t\t" << ntohs(icmp->un.echo.id) << endl;
		fout << "\t|- Sequence:\t\t\t\t" << ntohs(icmp->un.echo.sequence) << endl;

		print_data(buffer, size);

		fout << "\n*************************************************************************\n";
	}
}

void print_igmp_packet(unsigned char *buffer, int size)
{
	if(!fout.is_open())
		cout << ERROR_FILE;
	else
	{
		fout << "\n\n==============================igmp packet=============================\n";
		fout << "\nIGMP Header\n";

		struct igmphdr *igmp = (struct igmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

		fout << "\t|- Type:\t\t\t\t\t" << (unsigned int)(igmp->type) << endl;
		if((unsigned int)(igmp->type) == 11)
			fout << "\t|- TTL expired\n";
		else
			fout << "\t|- IGMP echo reply\n";
		fout << "\t|- Code:\t\t\t\t\t\t" << (unsigned int)(igmp->code) << endl;
		fout << "\t|- Checksum:\t\t\t\t" << ntohs(igmp->csum) << endl;
		fout << "\t|- Group:\t\t\t\t\t" << ntohs(igmp->group) << endl;

		print_data(buffer, size);

		fout << "\n************************************************************************\n";
	}
}

void print_data(unsigned char *buffer, int size)
{
	unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

	if(!fout.is_open())
		cout << ERROR_FILE;
	else
	{
		fout << "\nData\n";
		int remaining = size - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
		for(int i = 0; i < remaining; i++)
		{
			if(i != 0 && i%16 == 0)
				fout << "\n";
			std::hex(fout);
			fout << " " << (int)data[i] << "\t";
		}
		fout << endl;
	}
}

void signal_function(int sig)
{
	if(sig != SIGINT)
		return;
	else
	{
		cout << "\nTCP: " << tcp << ", UDP: " << udp << ", ICMP: " << icmp << ", IGMP: " << igmp
			<< ", Others: " << others << ", Total: " << total << ", Size all packet: "
			<< total_size_packet << " bytes\n";
		cout << "\n*** Details can be viewed in the file report.txt ***\n";
		exit(0);
	}
}
