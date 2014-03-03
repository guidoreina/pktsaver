#ifndef FS_OMEMFILE_H
#define FS_OMEMFILE_H

#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/uio.h>

namespace fs {
  class omemfile {
    public:
      // Constructor.
      omemfile();

      // Destructor.
      ~omemfile();

      // Open file.
      bool open(const char* pathname, mode_t mode);

      // Close file.
      bool close();

      // Write.
      ssize_t write(const void* buf, size_t count);

      // Write from multiple buffers.
      ssize_t writev(const struct iovec* iov, unsigned iovcnt);

    protected:
      static const off_t kFileIncrement = 256L * 1024L * 1024L;

      int _M_fd;
      void* _M_addr;

      off_t _M_filesize;
      off_t _M_off;

      // Increase file.
      bool increase();

    private:
      // Disable copy constructor and assignment operator.
      omemfile(const omemfile&);
      omemfile& operator=(const omemfile&);
  };

  inline omemfile::omemfile()
    : _M_fd(-1),
      _M_addr(MAP_FAILED)
  {
  }

  inline omemfile::~omemfile()
  {
    close();
  }

  inline ssize_t omemfile::writev(const struct iovec* iov, unsigned iovcnt)
  {
    size_t total = 0;
    for (unsigned i = 0; i < iovcnt; i++) {
      ssize_t ret;
      if ((ret = write(iov[i].iov_base, iov[i].iov_len)) != static_cast<ssize_t>(iov[i].iov_len)) {
        return ret;
      }

      total += ret;
    }

    return total;
  }
}

#endif // FS_OMEMFILE_H
