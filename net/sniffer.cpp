#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "net/sniffer.h"
#include "fs/file.h"

net::sniffer::sniffer()
{
  _M_fd = -1;

  _M_buf = MAP_FAILED;

  _M_frames = NULL;

  _M_idx = 0;

  _M_npackets = 0;

  _M_max_pcap_filesize = 0;

  _M_running = false;
}

net::sniffer::~sniffer()
{
  if (_M_buf != MAP_FAILED) {
    munmap(_M_buf, _M_ring_size);
  }

  if (_M_fd != -1) {
    close(_M_fd);
  }

  if (_M_frames) {
    free(_M_frames);
  }
}

bool net::sniffer::create(const char* interface, const char* pathname, size_t ring_size, size_t max_pcap_filesize)
{
  // Sanity checks.
  if ((ring_size < kMinRingSize) || (ring_size > kMaxRingSize)) {
    return false;
  }

  size_t len;
  if ((len = strlen(interface)) >= IFNAMSIZ) {
    return false;
  }

  size_t pathnamelen;
  if ((pathnamelen = strlen(pathname)) >= sizeof(_M_pathname)) {
    return false;
  }

  if (max_pcap_filesize > 0) {
    // Check that the file can be opened for reading/writing.
    fs::file f;
    if (!f.open(pathname, O_CREAT | O_RDWR)) {
      fprintf(stderr, "Couldn't open capture file %s for writing.\n", pathname);
      return false;
    }

    unlink(pathname);
  }

  // Create socket.
  if ((_M_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    return false;
  }

  // Get header length (only for TPACKET_V2).
#ifdef HAVE_TPACKET_V2
  if (!get_header_length()) {
    return false;
  }
#endif // HAVE_TPACKET_V2

  // Set packet version (only for TPACKET_V3 or TPACKET_V2).
#if defined(HAVE_TPACKET_V3) || defined(HAVE_TPACKET_V2)
  #ifdef HAVE_TPACKET_V3
    if (!set_packet_version(TPACKET_V3)) {
  #else
    if (!set_packet_version(TPACKET_V2)) {
  #endif
      return false;
    }
#endif // defined(HAVE_TPACKET_V3) || defined(HAVE_TPACKET_V2)

  // Get interface index.
  struct ifreq ifr;
  memcpy(ifr.ifr_name, interface, len + 1);

  if (ioctl(_M_fd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
    return false;
  }

  // Put the interface in promiscuous mode.
  struct packet_mreq mr;
  memset(&mr, 0, sizeof(struct packet_mreq));
  mr.mr_ifindex = ifr.ifr_ifindex;
  mr.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(_M_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(struct packet_mreq)) < 0) {
    perror("setsockopt");
    return false;
  }

  // Setup packet ring.
  if (!setup_packet_ring(ring_size)) {
    return false;
  }

  if (max_pcap_filesize == 0) {
    // Open capture file (unlimited file size).
    if (!_M_pcap_file.open(pathname)) {
      fprintf(stderr, "Couldn't open capture file %s for writing.\n", pathname);
      return false;
    }
  } else {
    if (!_M_pkts.allocate(max_pcap_filesize)) {
#if __WORDSIZE == 64
      fprintf(stderr, "Couldn't preallocate %llu bytes for the capture file.\n", max_pcap_filesize);
#else
      fprintf(stderr, "Couldn't preallocate %u bytes for the capture file.\n", max_pcap_filesize);
#endif

      return false;
    }

    // Save pathname.
    memcpy(_M_pathname, pathname, pathnamelen + 1);

    _M_max_pcap_filesize = max_pcap_filesize;
  }

  // Bind.
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(struct sockaddr_ll));
  addr.sll_family = PF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = ifr.ifr_ifindex;
  addr.sll_pkttype = PACKET_HOST | PACKET_OUTGOING;
  if (bind(_M_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr_ll)) < 0) {
    perror("bind");
    return false;
  }

  return true;
}

bool net::sniffer::start()
{
  struct pollfd pfd;
  pfd.fd = _M_fd;
  pfd.events = POLLIN | POLLRDNORM | POLLERR;
  pfd.revents = 0;

  _M_running = true;
  do {
    // While we don't have a new packet...
    if (!have_new_packet()) {
      // Wait.
      poll(&pfd, 1, -1);
      continue;
    }

    // Process packet(s).
    if (!process_packets()) {
      _M_running = false;
      break;
    }

    // Mark block/frame as free.
    mark_as_free();

    _M_idx = (_M_idx + 1) % _M_max_idx;
  } while (_M_running);

#if SHOW_STATISTICS
  show_statistics();
#endif

  if (_M_max_pcap_filesize > 0) {
    if (!_M_pcap_file.write_packets(_M_pathname, _M_pkts)) {
      fprintf(stderr, "Couldn't write packets to the capture file %s.\n", _M_pathname);
      return false;
    }
  }

  return true;
}

#ifdef HAVE_TPACKET_V2
  bool net::sniffer::get_header_length()
  {
    socklen_t optlen = sizeof(_M_hdrlen);
    return (getsockopt(_M_fd, SOL_PACKET, PACKET_HDRLEN, &_M_hdrlen, &optlen) == 0);
  }
#endif // HAVE_TPACKET_V2

bool net::sniffer::set_packet_version(tpacket_versions version)
{
  int val = version;
  return (setsockopt(_M_fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(int)) == 0);
}

bool net::sniffer::setup_packet_ring(size_t ring_size)
{
  // Calculate frame size.
  _M_frame_size = TPACKET_ALIGN(TPACKET_HDRLEN) + TPACKET_ALIGN(ETH_DATA_LEN);
  size_t n;
  for (n = 8; n < _M_frame_size; n *= 2);
  _M_frame_size = n;

  // Calculate number of blocks and number of frames.
  _M_nblocks = ring_size / kBlockSize;
  _M_ring_size = _M_nblocks * kBlockSize;
  _M_nframes = _M_ring_size / _M_frame_size;

#ifdef DEBUG_RING
  printf("# blocks: %u, sizeof(block) = %u.\n", _M_nblocks, kBlockSize);
  printf("# frames: %u, sizeof(frame) = %u.\n", _M_nframes, _M_frame_size);
  printf("Ring size = %u.\n", _M_ring_size);
#endif // DEBUG_RING

#ifdef HAVE_TPACKET_V3
  struct tpacket_req3 req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = kBlockSize;
  req.tp_block_nr = _M_nblocks;
  req.tp_frame_size = _M_frame_size;
  req.tp_frame_nr = _M_nframes;
  req.tp_retire_blk_tov = 100;
  req.tp_feature_req_word = 0;
#else
  struct tpacket_req req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = kBlockSize;
  req.tp_block_nr = _M_nblocks;
  req.tp_frame_size = _M_frame_size;
  req.tp_frame_nr = _M_nframes;
#endif

  // Setup PACKET_MMAP.
  if (setsockopt(_M_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
    return false;
  }

  if ((_M_buf = mmap(NULL, _M_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, _M_fd, 0)) == MAP_FAILED) {
    return false;
  }

  // Allocate frames.
#ifdef HAVE_TPACKET_V3
  return allocate_frames(_M_nblocks, kBlockSize);
#else
  return allocate_frames(_M_nframes, _M_frame_size);
#endif
}

bool net::sniffer::allocate_frames(size_t num, size_t size)
{
  if ((_M_frames = reinterpret_cast<struct iovec*>(malloc(num * sizeof(struct iovec)))) == NULL) {
    return false;
  }

  for (size_t i = 0; i < num; i++) {
    _M_frames[i].iov_base = reinterpret_cast<uint8_t*>(_M_buf) + (i * size);
    _M_frames[i].iov_len = size;
  }

  _M_max_idx = num;

  return true;
}

#ifdef HAVE_TPACKET_V3
  bool net::sniffer::walk_block()
  {
    _M_hdr = reinterpret_cast<struct tpacket3_hdr*>(reinterpret_cast<uint8_t*>(_M_block_desc) + _M_block_desc->bh1.offset_to_first_pkt);

    uint32_t num_pkts = _M_block_desc->bh1.num_pkts;
    for (uint32_t i = 0; i < num_pkts; i++) {
      // IP packet?
      const struct ethhdr* eth;
      eth = reinterpret_cast<const struct ethhdr*>(reinterpret_cast<const uint8_t*>(_M_hdr) + _M_hdr->tp_mac);
      if (eth->h_proto == htons(ETH_P_IP)) {
        if (!process_ip_packet(eth, _M_hdr->tp_snaplen)) {
          return false;
        }
      } else if (!_M_filter.have_filter()) {
        if (!write_packet(eth, _M_hdr->tp_snaplen)) {
          return false;
        }
      }

      _M_hdr = reinterpret_cast<struct tpacket3_hdr*>(reinterpret_cast<uint8_t*>(_M_hdr) + _M_hdr->tp_next_offset);
    }

    return true;
  }
#else
  bool net::sniffer::process_frame()
  {
    // IP packet?
    const struct ethhdr* eth;
    eth = reinterpret_cast<const struct ethhdr*>(reinterpret_cast<const uint8_t*>(_M_hdr) + _M_hdr->tp_mac);
    if (eth->h_proto == htons(ETH_P_IP)) {
      return process_ip_packet(eth, _M_hdr->tp_snaplen);
    } else if (!_M_filter.have_filter()) {
      return write_packet(eth, _M_hdr->tp_snaplen);
    }

    return true;
  }
#endif

bool net::sniffer::process_ip_packet(const struct ethhdr* eth, size_t ethlen)
{
  if (ethlen < ETH_HLEN + sizeof(struct iphdr)) {
    return true;
  }

  const uint8_t* pkt = reinterpret_cast<const uint8_t*>(eth);
  const struct iphdr* ip_header = reinterpret_cast<const struct iphdr*>(pkt + ETH_HLEN);
  size_t iphdrlen = ip_header->ihl * 4;
  size_t iplen = ethlen - ETH_HLEN;
  if (iplen < iphdrlen) {
    return true;
  }

  // If the packet doesn't match the filter...
  if (!_M_filter.match(ip_header, iphdrlen, iplen)) {
    // Do nothing.
    return true;
  }

#if DEBUG_TRAFFIC
  show_packet(ip_header, iphdrlen, iplen);
#endif

  return write_packet(eth, ethlen);
}

void net::sniffer::show_packet(const struct iphdr* ip_header, size_t iphdrlen, size_t iplen)
{
  const uint8_t* saddr = reinterpret_cast<const uint8_t*>(&ip_header->saddr);
  const uint8_t* daddr = reinterpret_cast<const uint8_t*>(&ip_header->daddr);

  // TCP?
  if (ip_header->protocol == 0x06) {
    if (iplen < iphdrlen + sizeof(struct tcphdr)) {
      return;
    }

    const struct tcphdr* tcp_header;
    tcp_header = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const uint8_t*>(ip_header) + iphdrlen);
    size_t tcphdrlen = tcp_header->doff * 4;
    if (iplen < iphdrlen + tcphdrlen) {
      return;
    }

    unsigned short sport = ntohs(tcp_header->source);
    unsigned short dport = ntohs(tcp_header->dest);

    printf("[TCP] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           saddr[0], saddr[1], saddr[2], saddr[3], sport,
           daddr[0], daddr[1], daddr[2], daddr[3], dport);
  } else if (ip_header->protocol == 0x11) {
    // UDP.
    if (iplen < iphdrlen + sizeof(struct udphdr)) {
      return;
    }

    const struct udphdr* udp_header;
    udp_header = reinterpret_cast<const struct udphdr*>(reinterpret_cast<const uint8_t*>(ip_header) + iphdrlen);

    unsigned short sport = ntohs(udp_header->source);
    unsigned short dport = ntohs(udp_header->dest);

    printf("[UDP] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           saddr[0], saddr[1], saddr[2], saddr[3], sport,
           daddr[0], daddr[1], daddr[2], daddr[3], dport);
  } else if (ip_header->protocol == 0x01) {
    // ICMP.
    printf("[ICMP] %u.%u.%u.%u -> %u.%u.%u.%u\n",
           saddr[0], saddr[1], saddr[2], saddr[3],
           daddr[0], daddr[1], daddr[2], daddr[3]);
  } else {
    printf("[protocol: 0x%02x] %u.%u.%u.%u -> %u.%u.%u.%u\n",
           ip_header->protocol,
           saddr[0], saddr[1], saddr[2], saddr[3],
           daddr[0], daddr[1], daddr[2], daddr[3]);
  }
}

bool net::sniffer::show_statistics()
{
#ifdef HAVE_TPACKET_V3
  struct tpacket_stats_v3 stats;
#else
  struct tpacket_stats stats;
#endif

  socklen_t optlen = sizeof(stats);
  if (getsockopt(_M_fd, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen) < 0) {
    return false;
  }

  printf("%u packets received.\n", stats.tp_packets);
  printf("%u packets matched the filter.\n", _M_npackets);
  printf("%u packets dropped by kernel.\n", stats.tp_drops);

  return true;
}
