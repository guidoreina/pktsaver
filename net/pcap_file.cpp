#include <stdlib.h>
#include "net/pcap_file.h"

const struct net::pcap_file::pcap_hdr_t net::pcap_file::_M_pcap_hdr = {
  kMagicNumber,
  kVersionMajor,
  kVersionMinor,
  kThisZone,
  kSigfigs,
  kSnaplen,
  kLinkType
};

bool net::pcap_file::open(const char* pathname)
{
#ifdef USE_OMEMFILE
  if (!fs::omemfile::open(pathname, 0644)) {
#else
  if (!fs::file::open(pathname, O_CREAT | O_TRUNC | O_WRONLY, 0644)) {
#endif
    return false;
  }

  return write_header();
}

bool net::pcap_file::write_packets(const char* pathname, const string::buffer& pkts)
{
#ifdef USE_OMEMFILE
  if (!fs::omemfile::open(pathname, 0644)) {
#else
  if (!fs::file::open(pathname, O_CREAT | O_TRUNC | O_WRONLY, 0644)) {
#endif
    return false;
  }

  struct iovec iov[2];
  iov[0].iov_base = const_cast<struct pcap_hdr_t*>(&_M_pcap_hdr);
  iov[0].iov_len = sizeof(struct pcap_hdr_t);

  iov[1].iov_base = const_cast<char*>(pkts.data());
  iov[1].iov_len = pkts.count();

  return (writev(iov, 2) == static_cast<ssize_t>(sizeof(struct pcap_hdr_t) + pkts.count()));
}

bool net::pcap_file::write_packet(uint32_t sec, uint32_t usec, const void* buf, size_t count)
{
  struct pcaprec_hdr_t hdr;
  hdr.tv.ts_sec = sec;
  hdr.tv.ts_usec = usec;
  hdr.len = count;
  hdr.snaplen = count;

  struct iovec iov[2];
  iov[0].iov_base = &hdr;
  iov[0].iov_len = sizeof(struct pcaprec_hdr_t);

  iov[1].iov_base = const_cast<void*>(buf);
  iov[1].iov_len = count;

  return (writev(iov, 2) == static_cast<ssize_t>(sizeof(struct pcaprec_hdr_t) + count));
}

bool net::pcap_file::append_packet(uint32_t sec, uint32_t usec, const void* buf, size_t count, string::buffer& pkts)
{
  // If the packet doesn't fit...
  if (pkts.count() + sizeof(struct pcaprec_hdr_t) + count > pkts.size()) {
    return false;
  }

  char* end = pkts.end();

  // Fill header.
  struct pcaprec_hdr_t* hdr = reinterpret_cast<struct pcaprec_hdr_t*>(end);
  hdr->tv.ts_sec = sec;
  hdr->tv.ts_usec = usec;
  hdr->len = count;
  hdr->snaplen = count;

  end += sizeof(struct pcaprec_hdr_t);

  memcpy(end, buf, count);

  pkts.increment_count(sizeof(struct pcaprec_hdr_t) + count);

  return true;
}
