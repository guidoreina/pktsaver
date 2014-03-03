#ifndef NET_FILTER_H
#define NET_FILTER_H

#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>

namespace net {
  class filter {
    public:
      // Constructor.
      filter();

      // Destructor.
      ~filter();

      // Parse filter.
      bool parse(const char* filter);

      // Have filter?
      bool have_filter() const;

      // Match filter.
      bool match(const struct iphdr* ip_header, size_t iphdrlen, size_t iplen) const;

    private:
      bool _M_filter;
      bool _M_icmp;

      struct port_pair {
        bool sport;
        bool dport;
      };

      struct port_pair* _M_tcp;
      struct port_pair* _M_udp;

      // Free.
      void free();

      // Initialize.
      bool init();

      // Install filter.
      void install_filter(bool tcp, bool udp, bool src, bool dest, uint16_t first, uint16_t last, bool val);

      // Set ports.
      void set_ports(uint16_t first, uint16_t last, bool val);

      // Set source ports.
      void set_src_ports(uint16_t first, uint16_t last, bool val);

      // Set destination ports.
      void set_dest_ports(uint16_t first, uint16_t last, bool val);

      // Set TCP ports.
      void set_tcp_ports(uint16_t first, uint16_t last, bool val);

      // Set TCP source ports.
      void set_tcp_src_ports(uint16_t first, uint16_t last, bool val);

      // Set TCP destination ports.
      void set_tcp_dest_ports(uint16_t first, uint16_t last, bool val);

      // Set UDP ports.
      void set_udp_ports(uint16_t first, uint16_t last, bool val);

      // Set UDP source ports.
      void set_udp_src_ports(uint16_t first, uint16_t last, bool val);

      // Set UDP destination ports.
      void set_udp_dest_ports(uint16_t first, uint16_t last, bool val);

      // Disable copy constructor and assignment operator.
      filter(const filter&);
      filter& operator=(const filter&);
  };

  inline filter::filter()
    : _M_tcp(NULL),
      _M_udp(NULL)
  {
  }

  inline filter::~filter()
  {
    free();
  }

  inline bool filter::have_filter() const
  {
    return _M_filter;
  }

  inline void filter::set_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_tcp[i].sport = val;
      _M_tcp[i].dport = val;
      _M_udp[i].sport = val;
      _M_udp[i].dport = val;
    }
  }

  inline void filter::set_src_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_tcp[i].sport = val;
      _M_udp[i].sport = val;
    }
  }

  inline void filter::set_dest_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_tcp[i].dport = val;
      _M_udp[i].dport = val;
    }
  }

  inline void filter::set_tcp_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_tcp[i].sport = val;
      _M_tcp[i].dport = val;
    }
  }

  inline void filter::set_tcp_src_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_tcp[i].sport = val;
    }
  }

  inline void filter::set_tcp_dest_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_tcp[i].dport = val;
    }
  }

  inline void filter::set_udp_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_udp[i].sport = val;
      _M_udp[i].dport = val;
    }
  }

  inline void filter::set_udp_src_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_udp[i].sport = val;
    }
  }

  inline void filter::set_udp_dest_ports(uint16_t first, uint16_t last, bool val)
  {
    for (unsigned i = first; i <= last; i++) {
      _M_udp[i].dport = val;
    }
  }
}

#endif // NET_FILTER_H
