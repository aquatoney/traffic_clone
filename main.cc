#include "signal.h"
#include "string.h"
#include "stdio.h"
#include <pcap.h>
#include <linux/ip.h>

#include <string>
#include <unordered_map>

using namespace std;


pcap_t* desc;
pcap_dumper_t* dump_file;
unsigned long long cur_pkt_num;



struct clone_settings {
  int setting;
  unsigned long max_cap;
};

#define LIVE_CAP 1
#define OFFLINE_CAP 2
#define WRITE_CAP 4

struct clone_settings paras;

struct ip_pair {
  uint32_t t_sip;
  uint32_t t_dip;
};

unordered_map<uint64_t, ip_pair*> ip_pairs; 

uint64_t MIN_IP = 0;
uint64_t MAX_IP = 0;

void close_stat()
{
    if (WRITE_CAP & paras.setting) {
      pcap_dump_close(dump_file);
    } 
}

int is_ip_pkt(unsigned char* data, unsigned data_len)
{ 
  if (data_len < MIN_IP_PKT_LEN) return -1;
  return (data[12] == 0x08 && data[13] == 0x00);
}

void clone_handler(unsigned char* par, struct pcap_pkthdr* hdr, unsigned char* data)
{
  if (paras.max_cap != 0 && ++cur_pkt_num >= paras.max_cap) {
    pcap_breakloop(desc);
  }

  if (is_ip_pkt(data, hdr->len)) {
    struct iphdr* ip_hdr = (struct iphdr*)(data+14);
    uint64_t key = ip_hdr->saddr;
    key = key << 32 + ip_hdr->daddr;
    struct ip_pair* p;
    auto p_iter = ip_pairs.find(key);
    if (p_iter != ip_pairs.end()) {
      p = p_iter->second;
    }
    else {
      p = (struct ip_pair*)malloc(sizeof(struct ip_pair));
      p->t_sip = ip_hdr->saddr;
      p->t_dip = ip_hdr->daddr;

    }
    pcap_dump((unsigned char *)dump_file, hdr, data);
  }

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
  memset(&stat, 0, sizeof(struct statistic));

  if (OFFLINE_CAP & paras.setting) {
    desc = pcap_open_offline(paras.read_file, errbuf);
    if (desc == NULL) {
      printf("Invalid read filename: %s\n", paras.read_file);
      exit(0);
    }
  }

  if (WRITE_CAP & paras.setting) {
    dump_file = pcap_dump_open(desc, paras.write_file);
    if (dump_file == NULL) {
      printf("Invalid write filename: %s\n", paras.write_file);
      exit(0);
    }
  }
}


int main(int argc, char const *argv[])
{ 
  signal(SIGINT, ctrl_c_handler);
  memset(&paras, 0, sizeof(struct clone_settings));


  int i = 1;
  while (i < argc) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      exit_print_usage();
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
    else {
      exit_error_usage();
    }
  }

  init_clone();

  pcap_loop(desc, -1, (pcap_handler) clone_handler, NULL);

  close_clone();

  summary(&stat);

  return 0;
}