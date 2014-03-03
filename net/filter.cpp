#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <limits.h>
#include "net/filter.h"
#include "macros/macros.h"

bool net::filter::parse(const char* filter)
{
  if (!init()) {
    return false;
  }

  bool tcp = false;
  bool udp = false;
  bool src = false;
  bool dest = false;
  unsigned first = 0;
  unsigned last = 0;

  int state = 0; // Initial state.
  while (*filter) {
    switch (state) {
      case 0: // Initial state.
        switch (*filter) {
          case 'i':
          case 'I':
            filter++;
            state = 1; // ICMP.
            break;
          case 's':
          case 'S':
            tcp = true;
            udp = true;
            src = true;
            dest = false;

            filter++;
            state = 4; // "port".
            break;
          case 'd':
          case 'D':
            tcp = true;
            udp = true;
            src = false;
            dest = true;

            filter++;
            state = 4; // "port".
            break;
          case 't':
          case 'T':
            tcp = true;
            udp = false;
            src = false;
            dest = false;

            filter++;
            state = 2; // TCP.
            break;
          case 'u':
          case 'U':
            tcp = false;
            udp = true;
            src = false;
            dest = false;

            filter++;
            state = 3; // UDP.
            break;
          case '0':
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '6':
          case '7':
          case '8':
          case '9':
            tcp = true;
            udp = true;
            src = true;
            dest = true;

            first = *filter - '0';

            filter++;
            state = 5; // Port or range of ports.
            break;
          case ' ':
          case '\t':
            filter++;
            break;
          default:
            return false;
        }

        break;
      case 1: // ICMP.
        if (((filter[0] != 'c') && (filter[0] != 'C')) || \
            ((filter[1] != 'm') && (filter[1] != 'M')) || \
            ((filter[2] != 'p') && (filter[2] != 'P'))) {
          return false;
        }

        if ((filter[3]) && (!IS_WHITE_SPACE(filter[3]))) {
          return false;
        }

        _M_icmp = true;

        filter += 3;
        state = 0; // Initial state.
        break;
      case 2: // TCP.
        if (((filter[0] != 'c') && (filter[0] != 'C')) || \
            ((filter[1] != 'p') && (filter[1] != 'P'))) {
          return false;
        }

        if ((!filter[2]) || (IS_WHITE_SPACE(filter[2]))) {
          set_tcp_ports(0, USHRT_MAX, true);

          filter += 2;
          state = 0; // Initial state.
        } else if (filter[2] == ':') {
          if ((filter[3] == 's') || (filter[3] == 'S')) {
            src = true;

            filter += 4;
            state = 4; // "port".
          } else if ((filter[3] == 'd') || (filter[3] == 'D')) {
            dest = true;

            filter += 4;
            state = 4; // "port".
          } else if (IS_DIGIT(filter[3])) {
            src = true;
            dest = true;

            first = filter[3] - '0';

            filter += 4;
            state = 5; // Port or range of ports.
          } else {
            return false;
          }
        } else {
          return false;
        }

        break;
      case 3: // UDP.
        if (((filter[0] != 'd') && (filter[0] != 'D')) || \
            ((filter[1] != 'p') && (filter[1] != 'P'))) {
          return false;
        }

        if ((!filter[2]) || (IS_WHITE_SPACE(filter[2]))) {
          set_udp_ports(0, USHRT_MAX, true);

          filter += 2;
          state = 0; // Initial state.
        } else if (filter[2] == ':') {
          if ((filter[3] == 's') || (filter[3] == 'S')) {
            src = true;

            filter += 4;
            state = 4; // "port".
          } else if ((filter[3] == 'd') || (filter[3] == 'D')) {
            dest = true;

            filter += 4;
            state = 4; // "port".
          } else if (IS_DIGIT(filter[3])) {
            src = true;
            dest = true;

            first = filter[3] - '0';

            filter += 4;
            state = 5; // Port or range of ports.
          } else {
            return false;
          }
        } else {
          return false;
        }

        break;
      case 4: // "port".
        if (((filter[0] != 'p') && (filter[0] != 'P')) || \
            ((filter[1] != 'o') && (filter[1] != 'O')) || \
            ((filter[2] != 'r') && (filter[2] != 'R')) || \
            ((filter[3] != 't') && (filter[3] != 'T')) || \
             (filter[4] != ':') || \
            (!IS_DIGIT(filter[5]))) {
          return false;
        }

        first = filter[5] - '0';

        filter += 6;
        state = 5; // Port or range of ports.
        break;
      case 5: // Port or range of ports.
        while (IS_DIGIT(*filter)) {
          if ((first = (first * 10) + (*filter - '0')) > USHRT_MAX) {
            return false;
          }

          filter++;
        }

        if (first == 0) {
          return false;
        }

        if (*filter == '-') {
          last = 0;

          filter++;
          state = 6; // Range of ports.
        } else if ((!*filter) || (IS_WHITE_SPACE(*filter))) {
          install_filter(tcp, udp, src, dest, first, first, true);

          state = 0; // Initial state.
        } else {
          return false;
        }

        break;
      case 6: // Range of ports.
        while (IS_DIGIT(*filter)) {
          if ((last = (last * 10) + (*filter - '0')) > USHRT_MAX) {
            return false;
          }

          filter++;
        }

        if (last == 0) {
          return false;
        }

        if ((*filter) && (!IS_WHITE_SPACE(*filter))) {
          return false;
        }

        if (first > last) {
          return false;
        }

        install_filter(tcp, udp, src, dest, first, last, true);

        state = 0; // Initial state.
        break;
    }
  }

  if (state != 0) {
    return false;
  }

  _M_filter = true;
  return true;
}

bool net::filter::match(const struct iphdr* ip_header, size_t iphdrlen, size_t iplen) const
{
  if (!_M_filter) {
    return true;
  }

  switch (ip_header->protocol) {
    case 0x06: // TCP.
      {
        if (iplen < iphdrlen + sizeof(struct tcphdr)) {
          return false;
        }

        const struct tcphdr* tcp_header;
        tcp_header = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const uint8_t*>(ip_header) + iphdrlen);
        size_t tcphdrlen = tcp_header->doff * 4;
        if (iplen < iphdrlen + tcphdrlen) {
          return false;
        }

        uint16_t sport = ntohs(tcp_header->source);
        uint16_t dport = ntohs(tcp_header->dest);

        return ((_M_tcp[sport].sport) || (_M_tcp[dport].dport));
      }
    case 0x11: // UDP.
      {
        if (iplen < iphdrlen + sizeof(struct udphdr)) {
          return false;
        }

        const struct udphdr* udp_header;
        udp_header = reinterpret_cast<const struct udphdr*>(reinterpret_cast<const uint8_t*>(ip_header) + iphdrlen);

        uint16_t sport = ntohs(udp_header->source);
        uint16_t dport = ntohs(udp_header->dest);

        return ((_M_udp[sport].sport) || (_M_udp[dport].dport));
      }
    case 0x01: // ICMP.
      return _M_icmp;
    default:
      return false;
  }
}

void net::filter::free()
{
  if (_M_tcp) {
    ::free(_M_tcp);
    _M_tcp = NULL;
  }

  if (_M_udp) {
    ::free(_M_udp);
    _M_udp = NULL;
  }
}

bool net::filter::init()
{
  free();

  if ((_M_tcp = reinterpret_cast<struct port_pair*>(malloc((USHRT_MAX + 1) * sizeof(struct port_pair)))) == NULL) {
    return false;
  }

  if ((_M_udp = reinterpret_cast<struct port_pair*>(malloc((USHRT_MAX + 1) * sizeof(struct port_pair)))) == NULL) {
    return false;
  }

  _M_filter = false;
  _M_icmp = false;
  set_ports(0, USHRT_MAX, false);

  return true;
}

void net::filter::install_filter(bool tcp, bool udp, bool src, bool dest, uint16_t first, uint16_t last, bool val)
{
  if ((tcp) && (udp)) {
    if ((src) && (dest)) {
      set_ports(first, last, val);
    } else if (src) {
      set_src_ports(first, last, val);
    } else if (dest) {
      set_dest_ports(first, last, val);
    }
  } else if (tcp) {
    if ((src) && (dest)) {
      set_tcp_ports(first, last, val);
    } else if (src) {
      set_tcp_src_ports(first, last, val);
    } else if (dest) {
      set_tcp_dest_ports(first, last, val);
    }
  } else if (udp) {
    if ((src) && (dest)) {
      set_udp_ports(first, last, val);
    } else if (src) {
      set_udp_src_ports(first, last, val);
    } else if (dest) {
      set_udp_dest_ports(first, last, val);
    }
  }
}
