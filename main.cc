#include "signal.h"
#include "string.h"
#include "stdio.h"
#include <cmath>
#include <pcap.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

#include <string>
#include <unordered_map>

using namespace std;


pcap_t* desc;
pcap_dumper_t* dump_file;
unsigned long long cur_pkt_num;

#define MIN_IP_PKT_LEN 40

struct clone_settings {
  int setting;
  unsigned net;
  unsigned long max_cap;
  char device[1024];
  char read_file[1024];
  char write_file[1024];
};

#define NET_POOL 1
#define OFFLINE_CAP 2
#define WRITE_CAP 4

struct clone_settings paras;

struct ip_info {
  uint32_t t_addr;
};

unordered_map<uint32_t, ip_info*> ip_pairs; 

unsigned MASK = 24;
uint64_t MAX_RAND = pow(2, MASK);
uint64_t NET_BASE = MAX_RAND;

uint64_t MIN_IP = 0;
uint64_t MAX_IP = MAX_RAND;

void close_clone()
{
    pcap_dump_close(dump_file);
}

int is_ip_pkt(unsigned char* data, unsigned data_len)
{ 
  if (data_len < MIN_IP_PKT_LEN) return -1;
  return (data[12] == 0x08 && data[13] == 0x00);
}

struct ip_info* create_or_locate_addr(uint32_t key)
{
  struct ip_info* p;
  auto p_iter = ip_pairs.find(key);
  if (p_iter != ip_pairs.end()) {
    p = p_iter->second;
  }
  else {
    p = (struct ip_info*)malloc(sizeof(struct ip_info));
    while (1) {
      p->t_addr = NET_BASE + rand() % MAX_RAND;
      if (ip_pairs.find(p->t_addr) == ip_pairs.end()) break;
    }
    ip_pairs.insert(make_pair(key, p));
  }
  return p;
}

void clone_handler(unsigned char* par, struct pcap_pkthdr* hdr, unsigned char* data)
{
  if (paras.max_cap != 0 && ++cur_pkt_num >= paras.max_cap) {
    pcap_breakloop(desc);
  }

  if (is_ip_pkt(data, hdr->len)) {
    struct iphdr* ip_hdr = (struct iphdr*)(data+14);
    
    struct ip_info* p;
    p = create_or_locate_addr(ntohl(ip_hdr->saddr));
    ip_hdr->saddr = htonl(p->t_addr);

    p = create_or_locate_addr(ntohl(ip_hdr->daddr));
    ip_hdr->daddr = htonl(p->t_addr);
  }

  pcap_dump((unsigned char *)dump_file, hdr, data);

}


void ctrl_c_handler(int sig)
{
    printf("\nwill shut down (ctrl-c again to kill)\n");
    pcap_breakloop(desc);
}


void init_clone()
{
  char errbuf[1024];
  desc = NULL;
  dump_file = NULL;
  cur_pkt_num = 0;


  if (!(OFFLINE_CAP & paras.setting && 
        WRITE_CAP & paras.setting && 
        NET_POOL & paras.setting)) {
    printf("-r, -w, -n are the MUST parameters\n");
    exit(0);
  }

  desc = pcap_open_offline(paras.read_file, errbuf);
  if (desc == NULL) {
    printf("Invalid read filename: %s\n", paras.read_file);
    exit(0);
  }

  dump_file = pcap_dump_open(desc, paras.write_file);
  if (dump_file == NULL) {
    printf("Invalid write filename: %s\n", paras.write_file);
    exit(0);
  }

  NET_BASE = paras.net;
  NET_BASE <<= MASK;
  MIN_IP += NET_BASE;
  MAX_IP += NET_BASE;

  printf("net_base: %lu, MIN_IP: %lu, MAX_IP: %lu\n", NET_BASE, MIN_IP, MAX_IP);

  srand (time(NULL));
}


int main(int argc, char const *argv[])
{ 
  signal(SIGINT, ctrl_c_handler);
  memset(&paras, 0, sizeof(struct clone_settings));


  int i = 1;
  while (i < argc) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      exit(0);
    }
    else if (strcmp(argv[i], "-r") == 0) {
      paras.setting |= OFFLINE_CAP;
      strcpy(paras.read_file, argv[i+1]);
      i += 2;
      continue;
    }
    else if (strcmp(argv[i], "-w") == 0) {
      paras.setting |= WRITE_CAP;
      strcpy(paras.write_file, argv[i+1]);
      i += 2;
      continue;
    }
    else if (strcmp(argv[i], "-c") == 0) {
      paras.max_cap = atoi(argv[i+1]);
      i += 2;
      continue;
    }
    /* net address pool n.X.X.X/24, n<255 */
    else if (strcmp(argv[i], "-n") == 0) {
      paras.setting |= NET_POOL;
      paras.net = atoi(argv[i+1]);
      i += 2;
      continue;
    }
    else {
      printf("wrong parameters\n");
      exit(0);
    }
  }

  init_clone();

  pcap_loop(desc, -1, (pcap_handler) clone_handler, NULL);

  close_clone();

  return 0;
}