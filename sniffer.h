#ifndef SNIFFER_H
#define SNIFFER_H

// 1. this function will sniff
void start_sniffing(int socket);

// 2. this function shows information about mac-address
void print_ethernet_packet(unsigned char *buffer);

// 3. this function shows information about ip packet
void print_ip_packet(unsigned char *buffer);

// 4. this function shows information about tcp packet
void print_tcp_packet(unsigned char *buffer, int size);

// 5. this function shows information about udp packet
void print_udp_packet(unsigned char *buffer, int size);

// 6. this function shows information about icmp packet
void print_icmp_packet(unsigned char *buffer, int size);

// 7. this function shows information about igmp packet
void print_igmp_packet(unsigned char *buffer, int size); 

// 8. what number protocol
void process_packet(unsigned char *buffer, int size);

// 9. print the hex value of the data
void print_data(unsigned char *buffer, int size);

// 10. to end the program at the signal
void signal_function(int sig);

#endif // SNIFFER_H
