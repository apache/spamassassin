#ifndef UTILS_H
#define UTILS_H

extern int libspamc_timeout;  /* default timeout in seconds */

ssize_t timeout_read(ssize_t (*reader)(int d, void *buf, size_t nbytes), 
                     int, void *, size_t );  

int full_read(int fd, unsigned char *buf, int min, int len);
int full_write(int fd, const unsigned char *buf, int len);

#endif
