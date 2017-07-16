#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include "net/sniffer.h"
#include "macros/macros.h"

static void usage(const char* program);
static void signal_handler(int nsignal);
static bool parse_size(const char* s, size_t min, size_t max, size_t& size);

net::sniffer gsniffer;

int main(int argc, char** argv)
{
  // Check arguments.
  if (argc < 3) {
    usage(argv[0]);
    return -1;
  }

  size_t ring_size = net::sniffer::kDefaultRingSize;
  size_t max_pcap_filesize = 0;

  int i = 1;

  int last = argc - 3;
  while (i <= last) {
    if (strcmp(argv[i], "-s") == 0) {
      // Last argument?
      if (i == last) {
        usage(argv[0]);
        return -1;
      }

      if (!parse_size(argv[i + 1], net::sniffer::kMinRingSize, net::sniffer::kMaxRingSize, ring_size)) {
        fprintf(stderr, "Invalid ring size %s.\n", argv[i + 1]);
        return -1;
      }

      i += 2;
    } else if (strcmp(argv[i], "-m") == 0) {
      // Last argument?
      if (i == last) {
        usage(argv[0]);
        return -1;
      }

      if (!parse_size(argv[i + 1], 0, ULONG_MAX, max_pcap_filesize)) {
        fprintf(stderr, "Invalid max-pcap-filesize %s.\n", argv[i + 1]);
        return -1;
      }

      i += 2;
    } else if (strcmp(argv[i], "-f") == 0) {
      // Last argument?
      if (i == last) {
        usage(argv[0]);
        return -1;
      }

      if (!gsniffer.filter().parse(argv[i + 1])) {
        fprintf(stderr, "Invalid filter (%s).\n", argv[i + 1]);
        return -1;
      }

      i += 2;
    } else {
      usage(argv[0]);
      return -1;
    }
  }

  // Create sniffer.
  if (!gsniffer.create(argv[argc - 2], argv[argc - 1], ring_size, max_pcap_filesize)) {
    fprintf(stderr, "Couldn't create sniffer.\n");
    return -1;
  }

  // Set signal handlers.
  struct sigaction act;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  act.sa_handler = signal_handler;
  sigaction(SIGTERM, &act, NULL);
  sigaction(SIGINT, &act, NULL);

  // Start sniffer.
  gsniffer.start();

  return 0;
}

void usage(const char* program)
{
  fprintf(stderr, "Usage: %s [options] <interface> <pathname>\n", program);
  fprintf(stderr, "\tOptions:\n");
  fprintf(stderr, "\t\t-s <ring-size>          Ring size in MiB (M) or GiB (G) (%u MB .. %u GB)\n",
          net::sniffer::kMinRingSize / (1024L * 1024L),
          net::sniffer::kMaxRingSize / (1024L * 1024L * 1024L));

  fprintf(stderr, "\t\t-m <max-pcap-filesize>  If bigger than 0, the program will preallocate max-pcap-filesize\n"
                  "\t\t\t\t\tbytes in memory and will only write the capture file upon reception\n"
                  "\t\t\t\t\tof a signal\n");
  fprintf(stderr, "\t\t-f \"<filter-list>\"      List of filters\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Filter list:\n");
  fprintf(stderr, "\tThe filter list is a list of filters separated by spaces.\n");
  fprintf(stderr, "\tSupported filters are:\n");
  fprintf(stderr, "\t\ticmp                            Filter ICMP protocol\n");
  fprintf(stderr, "\t\tport[-port]                     Filter TCP and UDP port or range of ports\n");
  fprintf(stderr, "\t\t(sport|dport):port[-port]       Filter TCP and UDP ports by source or\n"
                  "\t\t\t\t\t\tdestination port\n\n");
  fprintf(stderr, "\t\ttcp                             Filter TCP protocol\n");
  fprintf(stderr, "\t\ttcp:port[-port]                 Filter TCP port or range of ports\n");
  fprintf(stderr, "\t\ttcp:(sport|dport):port[-port]   Filter TCP port or range of ports by source or\n"
                  "\t\t\t\t\t\tdestination port\n\n");
  fprintf(stderr, "\t\tudp                             Filter UDP protocol\n");
  fprintf(stderr, "\t\tudp:port[-port]                 Filter UDP port or range of ports\n");
  fprintf(stderr, "\t\tudp:(sport|dport):port[-port]   Filter UDP port or range of ports by source or\n"
                  "\t\t\t\t\t\tdestination port\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\tIf no filter is specified, everything is captured.\n");
  fprintf(stderr, "\n");
}

void signal_handler(int nsignal)
{
  fprintf(stderr, "Signal received...\n");

  gsniffer.stop();
}

bool parse_size(const char* s, size_t min, size_t max, size_t& size)
{
  uint64_t n = 0;
  while (*s) {
    if (IS_DIGIT(*s)) {
      uint64_t tmp = (n * 10) + (*s - '0');

      // Overflow?
      if (tmp < n) {
        return false;
      }

      n = tmp;
    } else if (*s == 'M') {
      uint64_t tmp = n * (1024ULL * 1024ULL);

      // Overflow?
      if (tmp < n) {
        return false;
      }

      // If not the last character...
      if (*(s + 1)) {
        return false;
      }

      if ((tmp < min) || (tmp > max)) {
        return false;
      }

      size = static_cast<size_t>(tmp);
      return true;
    } else if (*s == 'G') {
      uint64_t tmp = n * (1024ULL * 1024ULL * 1024ULL);

      // Overflow?
      if (tmp < n) {
        return false;
      }

      // If not the last character...
      if (*(s + 1)) {
        return false;
      }

      if ((tmp < min) || (tmp > max)) {
        return false;
      }

      size = static_cast<size_t>(tmp);
      return true;
    } else {
      return false;
    }

    s++;
  }

  if ((n < min) || (n > max)) {
    return false;
  }

  size = static_cast<size_t>(n);
  return true;
}
