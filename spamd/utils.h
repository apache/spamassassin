#ifndef UTILS_H
#define UTILS_H

int full_read(int fd, unsigned char *buf, int min, int len);
int full_write(int fd, const unsigned char *buf, int len);

#endif
