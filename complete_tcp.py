import os, sys

syn_file = '/dev/shm/syn_tmp.txt'
fin_file = '/dev/shm/fin_tmp.txt'
tmp_file = '/dev/shm/pcap_tmp'

def syn_stream(pcap, syn_file):
  cmd = f'tshark -r {pcap} -Y tcp.connection.syn -Tfields -e tcp.stream > {syn_file}'
  print(cmd)
  os.system(cmd)

def fin_stream(pcap, fin_file):
  cmd = f'tshark -r {pcap} -Y tcp.connection.fin -Tfields -e tcp.stream > {fin_file}'
  print(cmd)
  os.system(cmd)

def output_stream(pcap, out):
  syn_fp = open(syn_file)
  fin_fp = open(fin_file)
  syn_streams = [str(stream)[:-1] for stream in syn_fp.readlines()]
  fin_streams = [str(stream)[:-1] for stream in fin_fp.readlines()]
  complete_streams = list(set(syn_streams) & set(fin_streams))[:100]
  sid_str =  ' '.join(complete_streams)

  cmd = f'tshark -r {pcap} -F pcap -w {out}.pcap -Y "tcp.stream in '
  cmd += '{' + sid_str + '}"'
  print(cmd)
  os.system(cmd)


if __name__ == '__main__':
  pcap_file = sys.argv[1]
  out_file = sys.argv[2]

  # syn_stream(pcap_file, syn_file)
  # fin_stream(pcap_file, fin_file)
  output_stream(pcap_file, out_file)