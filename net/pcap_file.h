#ifndef NET_PCAP_FILE_H
#define NET_PCAP_FILE_H

#include <stdint.h>

#ifdef USE_OMEMFILE
  #include "fs/omemfile.h"
#else
  #include "fs/file.h"
#endif

#include "string/buffer.h"

namespace net {
  class pcap_file
#ifdef USE_OMEMFILE
                  : protected fs::omemfile {
#else
                  : protected fs::file {
#endif
    public:
      // Constructor.
      pcap_file();

      // Open file.
      bool open(const char* pathname);

      // Write packets.
      bool write_packets(const char* pathname, const string::buffer& pkts);

      // Write packet.
      bool write_packet(uint32_t sec, uint32_t usec, const void* buf, size_t count);

      // Append packet.
      static bool append_packet(uint32_t sec, uint32_t usec, const void* buf, size_t count, string::buffer& pkts);

    private:
      static const uint32_t kMagicNumber = 0xa1b2c3d4;
      static const uint16_t kVersionMajor = 2;
      static const uint16_t kVersionMinor = 4;
      static const int32_t kThisZone = 0;
      static const uint32_t kSigfigs = 0;
      static const uint32_t kSnaplen = (64 * 1024) - 1;
      static const uint32_t kLinkType = 1; // LINKTYPE_ETHERNET

      struct pcap_hdr_t {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t linktype;
      };

      struct pcap_timeval_t {
        uint32_t ts_sec;
        uint32_t ts_usec;
      };

      struct pcaprec_hdr_t {
        struct pcap_timeval_t tv;
        uint32_t len;
        uint32_t snaplen;
      };

      static const struct pcap_hdr_t _M_pcap_hdr;

      // Write header.
      bool write_header();

      // Disable copy constructor and assignment operator.
      pcap_file(const pcap_file&);
      pcap_file& operator=(const pcap_file&);
  };

  inline pcap_file::pcap_file()
  {
  }

  inline bool pcap_file::write_header()
  {
    return (write(&_M_pcap_hdr, sizeof(struct pcap_hdr_t)) == static_cast<ssize_t>(sizeof(struct pcap_hdr_t)));
  }
}

#endif // NET_PCAP_FILE_H
