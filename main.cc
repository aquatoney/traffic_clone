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
uint64_t cur_pkt_num;
uint64_t amount = 0;

#define MIN_IP_PKT_LEN 40

struct clone_settings {
  int setting;
  unsigned net;
  unsigned clone_times;
  unsigned long max_cap;
  char device[1024];
  char read_file[1024];
  char write_file[1024];
};

#define NET_POOL 1
#define OFFLINE_CAP 2
#define WRITE_CAP 4
#define PRODUCE 8

struct clone_settings paras;

struct ip_info {
  uint32_t t_addr;
};

unordered_map<uint32_t, ip_info*> ip_pairs; 

unsigned MASK = 24;
uint64_t MAX_RAND = pow(2, MASK);
uint64_t NET_BASE = MAX_RAND;

uint64_t cur_clone_times = 0;
unsigned cur_net = 1;

struct timeval first_ts;
struct timeval last_ts;

long long diff_sec = 0;
long long diff_usec = 0;


uint64_t MIN_IP = 0;
uint64_t MAX_IP = MAX_RAND;

char loopback_head[4] = {0x02, 0x00, 0x00, 0x00}; 
unsigned ip_offset = 14;

void close_clone()
{
    pcap_dump_close(dump_file);
}

int is_ip_pkt(unsigned char* data, unsigned data_len)
{ 
  if (data_len < MIN_IP_PKT_LEN) return -1;
  if (memcmp(data, loopback_head, 4) == 0) {
    ip_offset = 4;
    return 1;
  }
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
    struct iphdr* ip_hdr = (struct iphdr*)(data+ip_offset);
    
    struct ip_info* p;
    p = create_or_locate_addr(ntohl(ip_hdr->saddr));
    ip_hdr->saddr = htonl(p->t_addr);

    p = create_or_locate_addr(ntohl(ip_hdr->daddr));
    ip_hdr->daddr = htonl(p->t_addr);
  }

  amount += hdr->len;
  if (PRODUCE & paras.setting) {
    gettimeofday(&hdr->ts, NULL);
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

  first_ts.tv_sec = 0;
  first_ts.tv_usec = 0;
  last_ts.tv_sec = 0;
  last_ts.tv_usec = 0;

  if (!(OFFLINE_CAP & paras.setting && 
        WRITE_CAP & paras.setting)) {
    printf("-r, -w are the MUST parameters\n");
    exit(0);
  }

  if (NET_POOL & paras.setting ^ PRODUCE & paras.setting == 0) {
    printf("-n, -k MUST be specified at least and at most one.\n");
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

  if (NET_POOL & paras.setting) {
    NET_BASE = paras.net;
  }
  else {
    NET_BASE = cur_net;
  }


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
    /* produce the traffic by the seed for k times */
    else if (strcmp(argv[i], "-k") == 0) {
      paras.setting |= PRODUCE;
      paras.clone_times = atoi(argv[i+1]);
      i += 2;
    }
    else {
      printf("wrong parameters\n");
      exit(0);
    }
  }

  init_clone();

  struct timeval start, now;

  gettimeofday(&start, NULL);


  if (NET_POOL & paras.setting) {
    pcap_loop(desc, -1, (pcap_handler) clone_handler, NULL);
  }
  else {
    while (cur_clone_times != paras.clone_times) {
      pcap_loop(desc, -1, (pcap_handler) clone_handler, NULL);
      ip_pairs.clear();
      cur_net ++;
      NET_BASE = cur_net;
      NET_BASE <<= MASK;
      MIN_IP += NET_BASE;
      MAX_IP += NET_BASE;
      cur_clone_times ++;
      pcap_close(desc);
      char errbuf[1024];
      desc = pcap_open_offline(paras.read_file, errbuf);
    }
  }
  

  close_clone();

  gettimeofday(&now, NULL);

  uint64_t time_s = (now.tv_sec-start.tv_sec) * 1000000 + (now.tv_usec-start.tv_usec);
  double tp = (double)amount*8*1000000/(time_s*1000*1000*1000);

  printf("%lu IP addresses\n", ip_pairs.size());
  printf("Amount: %.2f GB, Time: %.2f s, Throughput: %.2lf Gbps\n", 
         (float)amount/(1000*1000*1000), (float)time_s/1000000, tp);

  return 0;
}