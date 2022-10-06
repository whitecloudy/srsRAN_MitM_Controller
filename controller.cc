#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

struct sockaddr_in sa;
struct sockaddr_in sb;
struct sockaddr_in a,b;

int fa;
int fb;

void* worker(void *arg) {
  int *fsrc, *fdst;
  struct sockaddr_in *ssrc, *sdst;

  printf("Thread Created!\n");

  if ((uintptr_t)arg==12) {
    fsrc=&fa; fdst=&fb;
    ssrc=&a; sdst=&b;
  }
  else { /*(uintptr_t)arg==21*/
    fsrc=&fb; fdst=&fa;
    ssrc=&b; sdst=&a;
  }

  while(1) {
    char buf[65535];
    socklen_t sn=sizeof(*ssrc);
    int n=recvfrom(*fsrc,buf,sizeof(buf),0,(struct sockaddr *)ssrc,&sn);
    //int n=recv(*fsrc,buf,sizeof(buf),0);
    if(n>0 && sdst->sin_port>0) {
      sendto(*fdst,buf,n,0,(struct sockaddr *)sdst,sizeof(*sdst));
      //send(*fdst,buf,n,0);
      printf("fsrc: %d, fdst: %d, sdst port: %d, ssrc port: %d, size: %d\n", *fsrc, *fdst, sdst->sin_port, ssrc->sin_port, n);
    }
  }
  return NULL;
};

int main(int argc, char *argv[]) {
  memset(&a,0,sizeof(struct sockaddr_in));
  memset(&sa,0,sizeof(struct sockaddr_in));
  memset(&b,0,sizeof(struct sockaddr_in));
  memset(&sb,0,sizeof(struct sockaddr_in));

  if (argc!=4) {
    printf("Usage: %s bind-ip port-a port-b\n",argv[0]);
    exit(1);
  }

  else {
    printf("%s %s %s\n", argv[1], argv[2], argv[3]);
  }

  fa=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
  fb=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);

  a.sin_family=AF_INET;
  a.sin_addr.s_addr=inet_addr(argv[1]);
  a.sin_port=htons(8081);

  b.sin_family=AF_INET;
  b.sin_addr.s_addr=inet_addr(argv[1]);
  b.sin_port=htons(9091);

  sa.sin_family=AF_INET;
  sa.sin_addr.s_addr=inet_addr(argv[1]);
  //sa.sin_addr.s_addr=htonl(INADDR_ANY);
  sa.sin_port=htons(atoi(argv[2]));
  if(bind(fa,(struct sockaddr *)&sa,sizeof(sa))==-1) {
	  printf("Bind fa Error!\n");
    exit(2);
  }

  sb.sin_family=AF_INET;
  sb.sin_addr.s_addr=inet_addr(argv[1]);
  //sb.sin_addr.s_addr=htonl(INADDR_ANY);
  sb.sin_port=htons(atoi(argv[3]));
  if(bind(fb,(struct sockaddr *)&sb,sizeof(sb))==-1) {
	  printf("Bind fb Error!\n");
    exit(3);
  }

  //connect(fa, (struct sockaddr*)&sa, sizeof(sa));
  //connect(fb, (struct sockaddr*)&sb, sizeof(sb));

  pthread_t ab,ba;
  pthread_create(&ab,NULL,worker,(void*)12);
  pthread_create(&ba,NULL,worker,(void*)21);

  pthread_join(ab, NULL);
  pthread_join(ba, NULL);
  return 0;
}
