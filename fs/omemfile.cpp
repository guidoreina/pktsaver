#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "fs/omemfile.h"

bool fs::omemfile::open(const char* pathname, mode_t mode)
{
  if ((_M_fd = ::open(pathname, O_CREAT | O_TRUNC | O_RDWR, mode)) < 0) {
    return false;
  }

  _M_filesize = 0;
  _M_off = 0;

  return increase();
}

bool fs::omemfile::close()
{
  if (_M_addr != MAP_FAILED) {
    munmap(_M_addr, kFileIncrement);
    _M_addr = MAP_FAILED;
  }

  if (_M_fd != -1) {
    if (ftruncate(_M_fd, _M_off) < 0) {
      ::close(_M_fd);
      _M_fd = -1;

      return false;
    }

    if (::close(_M_fd) < 0) {
      return false;
    }

    _M_fd = -1;
  }

  return true;
}

ssize_t fs::omemfile::write(const void* buf, size_t count)
{
  const uint8_t* b = reinterpret_cast<const uint8_t*>(buf);
  off_t c = count;

  // If the data doesn't fit...
  off_t left;
  if ((left = _M_filesize - _M_off) < c) {
    if (left > 0) {
      memcpy(reinterpret_cast<uint8_t*>(_M_addr) + (_M_off % kFileIncrement), b, left);
      _M_off += left;

      b += left;
      c -= left;
    }

    if (!increase()) {
      return -1;
    }
  }

  memcpy(reinterpret_cast<uint8_t*>(_M_addr) + (_M_off % kFileIncrement), b, c);
  _M_off += c;

  return count;
}

bool fs::omemfile::increase()
{
  // Unmap previous region (if any).
  if (_M_addr != MAP_FAILED) {
    munmap(_M_addr, kFileIncrement);
    _M_addr = MAP_FAILED;
  }

  // Increment file size.
  off_t filesize = _M_filesize + kFileIncrement;
  if (ftruncate(_M_fd, filesize) < 0) {
    return false;
  }

  _M_filesize = filesize;

  // Map new region.
  if ((_M_addr = mmap(NULL, kFileIncrement, PROT_WRITE, MAP_SHARED, _M_fd, _M_off)) == MAP_FAILED) {
    return false;
  }

  return true;
}
