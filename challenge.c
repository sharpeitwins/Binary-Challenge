#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ptrace.h>

#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8

char 
*get_iface(void)
{
  char *iface; 
  char line[256];

  FILE* fp = popen("ip route | grep src | awk '{print $3}'", "r");
  
  iface = (char *)malloc((sizeof(line))*sizeof(char));
  
  if (fgets(line, sizeof(line), fp) != NULL)
  {
    iface = strncpy(iface, line, sizeof(iface));
  }
  
  pclose(fp);
  
  memset(&line[0], 0, sizeof(line));
  
  return iface;
  
  free(iface);
}

char 
*dest_ip(void)
{
  struct addrinfo hints, *res, *p;
  struct sockaddr_in sa;

  char ipstr[INET_ADDRSTRLEN];

  char *ip;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  getaddrinfo("www.google.com", NULL, &hints, &res);
  
  memset(&ipstr[0], 0, sizeof(ipstr));

  ip = (char *) malloc(sizeof(ipstr));

  for ( p = res; p != NULL; p = p->ai_next)
  {
    void *addr;

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
    addr = &(ipv4->sin_addr);

    inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
  
  }

  strncpy(ip, ipstr, strlen(ipstr));

  return ip;

  free(ip);
  freeaddrinfo(res);
}

uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;

  return (answer);
}

void
send_icmp(void)
{
  struct addrinfo hints, *res;
  struct icmp icmphdr;
  struct ip iphdr;
  struct sockaddr_in sin;

  struct ifreq idx;

  uint8_t *data, *packet;

  char *iface;
  char *d_ip;

  int sockfd, sd, datalen, status;

  const int n = 1;

  data = (uint8_t *) malloc (IP_MAXPACKET * sizeof (uint8_t));
  packet = (uint8_t *) malloc (IP_MAXPACKET * sizeof (uint8_t));
  d_ip = (char *) malloc(sizeof(char));
  iface = (char *) malloc(sizeof(char));

  d_ip = dest_ip();
  iface = get_iface();

  char *lo = "127.0.0.1";
 
  memset(&idx, 0, sizeof(idx));
  strncpy(idx.ifr_name, iface, IFNAMSIZ-1);
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  
  datalen = 23;
  data[0] = 't';
  data[1] = 'h';
  data[2] = 'u';
  data[3] = 'g';
  data[4] = '{';
  data[5] = '5';
  data[6] = 'm';
  data[7] = '0';
  data[8] = 'k';
  data[9] = '3';
  data[10] = '_';
  data[11] = 'w';
  data[12] = '3';
  data[13] = '3';
  data[14] = 'd';
  data[15] = '_';
  data[16] = '4';
  data[17] = '_';
  data[18] = '3';
  data[19] = 'v';
  data[20] = '3';
  data[21] = 'r';
  data[22] = '}';

  inet_pton(AF_INET, lo, &(iphdr.ip_src));
  inet_pton(AF_INET, d_ip, &(iphdr.ip_dst));

  iphdr.ip_v = 4;
  iphdr.ip_hl = 5;
  iphdr.ip_tos = 0;
  iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + datalen);
  iphdr.ip_id = htons(321);
  iphdr.ip_off = htons(0);
  iphdr.ip_ttl = 255;
  iphdr.ip_p = IPPROTO_ICMP;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);
   
  icmphdr.icmp_type = ICMP_ECHO;
  icmphdr.icmp_code = 0;
  icmphdr.icmp_id = htons(666);
  icmphdr.icmp_seq = htons(0);
  icmphdr.icmp_cksum = checksum((uint16_t *) (packet + IP4_HDRLEN), 
  /*########################################*/ ICMP_HDRLEN + datalen);
 
  memcpy (packet, &iphdr, IP4_HDRLEN);
  memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
  memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &n, 1);
  setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &idx, sizeof(idx));
  
  sendto(sd, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen,
  /*###*/ 0, (struct sockaddr *)&sin, sizeof(struct sockaddr));

  close(sd);
  
  free(d_ip);
  free(iface);
  free(data);
  free(packet);
}

void
main (void)
{
  send_icmp();
}

int
main_(void)
{
  FILE *txt = fopen("file.txt", "w");

  const char *text = "Your computer has been infected, please send BTC to \n\
                      address: dGh1Z3s3cnlfaDRyZDNyX24zckR9\n";

  fprintf(txt, "%s", text);

  fclose(txt);

  exit(1);
} 
