#ifndef NET_SNIFFER_H
#define NET_SNIFFER_H

#include <stdint.h>
#include <sys/uio.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <limits.h>
#include "net/filter.h"
#include "net/pcap_file.h"

namespace net {
  class sniffer {
    public:
      static const size_t kMinRingSize = 1024 * 1024; // 1 MB.

#if __WORDSIZE == 64
      static const size_t kMaxRingSize = 16L * 1024L * 1024L * 1024L; // 16 GB.
#else
      static const size_t kMaxRingSize = 1024 * 1024 * 1024; // 1 GB.
#endif

      static const size_t kDefaultRingSize = 256 * 1024 * 1024; // 256 MB.

      // Constructor.
      sniffer();

      // Destructor.
      ~sniffer();

      // Create.
      bool create(const char* interface, const char* pathname, size_t ring_size, size_t max_pcap_filesize = 0);

      // Start.
      bool start();

      // Stop.
      void stop();

      // Get filter.
      net::filter& filter();

    protected:
      static const size_t kBlockSize = 4096 << 2;

#ifdef HAVE_TPACKET_V3
      struct block_desc {
        uint32_t version;
        uint32_t offset_to_priv;
        struct tpacket_hdr_v1 bh1;
      };
#endif // HAVE_TPACKET_V3

      int _M_fd;

      void* _M_buf;
      size_t _M_ring_size;

      struct iovec* _M_frames;
      unsigned _M_nframes;
      size_t _M_frame_size;

      unsigned _M_nblocks;

#ifdef HAVE_TPACKET_V2
      int _M_hdrlen;
#endif // HAVE_TPACKET_V2

#ifdef HAVE_TPACKET_V3
      struct block_desc* _M_block_desc;
      struct tpacket3_hdr* _M_hdr;
#elif HAVE_TPACKET_V2
      struct tpacket2_hdr* _M_hdr;
#else
      struct tpacket_hdr* _M_hdr;
#endif

      size_t _M_idx;
      size_t _M_max_idx;

      unsigned _M_npackets;

      net::filter _M_filter;

      net::pcap_file _M_pcap_file;

      char _M_pathname[PATH_MAX + 1];
      size_t _M_max_pcap_filesize;
      string::buffer _M_pkts;

      bool _M_running;

#ifdef HAVE_TPACKET_V2
      // Get header length.
      bool get_header_length();
#endif // HAVE_TPACKET_V2

      // Set packet version.
      bool set_packet_version(tpacket_versions version);

      // Setup packet ring.
      bool setup_packet_ring(size_t ring_size);

      // Allocate frames.
      bool allocate_frames(size_t num, size_t size);

      // Have new packet.
      bool have_new_packet();

      // Process packet(s).
      bool process_packets();

#ifdef HAVE_TPACKET_V3
      // Walk block.
      bool walk_block();
#else
      // Process frame.
      bool process_frame();
#endif

      // Process IP packet.
      bool process_ip_packet(const struct ethhdr* eth, size_t ethlen);

      // Write packet.
      bool write_packet(const struct ethhdr* eth, size_t ethlen);

      // Mark as free.
      void mark_as_free();

      // Show packet.
      static void show_packet(const struct iphdr* ip_header, size_t iphdrlen, size_t iplen);

      // Show statistics.
      bool show_statistics();

    private:
      // Disable copy constructor and assignment operator.
      sniffer(const sniffer&);
      sniffer& operator=(const sniffer&);
  };

  inline void sniffer::stop()
  {
    _M_running = false;
  }

  inline net::filter& sniffer::filter()
  {
    return _M_filter;
  }

  inline bool sniffer::have_new_packet()
  {
#ifdef HAVE_TPACKET_V3
    _M_block_desc = reinterpret_cast<struct block_desc*>(_M_frames[_M_idx].iov_base);
    return ((_M_block_desc->bh1.block_status & TP_STATUS_USER) != 0);
#elif HAVE_TPACKET_V2
    _M_hdr = reinterpret_cast<struct tpacket2_hdr*>(_M_frames[_M_idx].iov_base);
    return ((_M_hdr->tp_status & TP_STATUS_USER) != 0);
#else
    _M_hdr = reinterpret_cast<struct tpacket_hdr*>(_M_frames[_M_idx].iov_base);
    return ((_M_hdr->tp_status & TP_STATUS_USER) != 0);
#endif
  }

  inline bool sniffer::process_packets()
  {
#ifdef HAVE_TPACKET_V3
    return walk_block();
#else
    return process_frame();
#endif
  }

  inline bool sniffer::write_packet(const struct ethhdr* eth, size_t ethlen)
  {
    _M_npackets++;

    uint32_t sec = _M_hdr->tp_sec;

#if defined(HAVE_TPACKET_V3) || defined(HAVE_TPACKET_V2)
    uint32_t usec = _M_hdr->tp_nsec / 1000;
#else
    uint32_t usec = _M_hdr->tp_usec;
#endif

    return (_M_max_pcap_filesize == 0) ?
            _M_pcap_file.write_packet(sec, usec, eth, ethlen) :
            _M_pcap_file.append_packet(sec, usec, eth, ethlen, _M_pkts);
  }

  inline void sniffer::mark_as_free()
  {
#ifdef HAVE_TPACKET_V3
    _M_block_desc->bh1.block_status = TP_STATUS_KERNEL;
#else
    _M_hdr->tp_status = TP_STATUS_KERNEL;
#endif
  }
}

#endif // NET_SNIFFER_H
