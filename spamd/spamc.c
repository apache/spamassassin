/*
 * This code is copyright 2001 by Craig Hughes
 * It is licensed for use with SpamAssassin according to the terms of the Perl Artistic License
 * The text of this license is included in the SpamAssassin distribution in the file named "License"
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

int main(int argc,char **argv)
{
  int port = 22874;
  int mysock = socket(PF_INET,SOCK_STREAM,0);
  ssize_t bytes;
  char buf[8192];
  struct sockaddr_in addr;
  int value=1;

  setsockopt(mysock,0,TCP_NODELAY,&value,sizeof(value));
  addr.sin_family = AF_INET;
  if(2==argc) port = atoi(argv[1]);
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  connect(mysock,(const struct sockaddr *)&addr,sizeof(addr));
  while((bytes=read(STDIN_FILENO,buf,8192)) > 0)
  {
    write(mysock,buf,bytes);
  }
  shutdown(mysock,SHUT_WR);
  while((bytes=read(mysock,buf,8192)) > 0)
  {
    write(STDOUT_FILENO,buf,bytes);
  }
  shutdown(mysock,SHUT_RD);
  return 0;
}
