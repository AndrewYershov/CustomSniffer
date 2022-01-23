/*
   Group LVIV
   10.12.2021
   YERSHOV Andrii

   GL C/C++ BaseCamp 3rd task
	Requirements:
		- Use Linux for implementation (or virtual machine with Linux);
		- Use GCC for compilation;
		- Use C/C++ for implementation;
		- Console application. No UI is required;
		- Use Make file for build/link/clean instructions;
		- Things to google: "RAW socket"
	1. Implement Sniffer application.
		- Application should use RAW sockets;
		- Application should monitor much data your PC sends/receives over the network;
		- Application should summarize all packets sizes to have calculation results;
		- Application should provide statistics in real time.
*/
#include "sniffer.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h> // 3-rd parametr
#include <unistd.h> // hostname
#include <iostream>
#include <csignal>


int main()
{
	using std::cout;
	using std::endl;

	char hostname[100]; // for name my PC(host)

	cout << "Creating RAW socket ...\n";
	int sniffer = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sniffer == -1)
	{
		cout << "Failed to create RAW socket!\n";
		return -1;
	}
	cout << "All right. RAW socket is created.\n";

	if(gethostname(hostname, sizeof(hostname)) == -1)
	{
		cout << "Error geting hostname!\n";
		return -1;
	}
	cout << "Host name: " << hostname << endl;
	cout << "Started sniffing ...\n";

	signal(SIGINT, signal_function);
	start_sniffing(sniffer);

	close(sniffer);


	return 0;
}
