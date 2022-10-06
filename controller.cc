#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define LOOPBACK_IP ("127.123.123.24")

#define FAKE_UE_PORT (8081)
#define FAKE_gNB_PORT (9091)
#define FAKE_UE_SERVER_PORT (8080)
#define FAKE_gNB_SERVER_PORT (9090)


struct sockaddr_in fake_UE_server_addr;
struct sockaddr_in fake_gNB_server_addr;
struct sockaddr_in fake_UE_addr, fake_gNB_addr;

int fake_UE_server_sock;
int fake_gNB_server_sock;

void* worker(void *arg) {
  int *fake_src_sock, *fake_dst_sock;
  struct sockaddr_in *fake_src_addr, *fake_dst_addr;

  printf("Thread Created!\n");

  if ((uintptr_t)arg==12) {
    fake_src_sock=&fake_UE_server_sock; 
    fake_dst_sock=&fake_gNB_server_sock;

    fake_src_addr=&fake_UE_addr;
    fake_dst_addr=&fake_gNB_addr;
  }
  else { /*(uintptr_t)arg==21*/
    fake_src_sock=&fake_gNB_server_sock; 
    fake_dst_sock=&fake_UE_server_sock;

    fake_src_addr=&fake_gNB_addr;
    fake_dst_addr=&fake_UE_addr;
  }

  while(1) {
    char buf[65535];
    socklen_t sn=sizeof(*fake_src_addr);
    int n=recvfrom(*fake_src_sock,buf,sizeof(buf),0,(struct sockaddr *)fake_src_addr,&sn);
    //int n=recv(*fake_src_sock,buf,sizeof(buf),0);
    if(n>0 && fake_dst_addr->sin_port>0) {
      sendto(*fake_dst_sock,buf,n,0,(struct sockaddr *)fake_dst_addr,sizeof(*fake_dst_addr));

      printf("fake_src_sock: %d, fake_dst_sock: %d, fake_dst_addr port: %d, fake_src_addr port: %d, size: %d\n", *fake_src_sock, *fake_dst_sock, fake_dst_addr->sin_port, fake_src_addr->sin_port, n);
    }
  }
  return NULL;
};

int main(int argc, char *argv[]) {
  memset(&fake_UE_addr,0,sizeof(struct sockaddr_in));
  memset(&fake_UE_server_addr,0,sizeof(struct sockaddr_in));
  memset(&fake_gNB_addr,0,sizeof(struct sockaddr_in));
  memset(&fake_gNB_server_addr,0,sizeof(struct sockaddr_in));


  fake_UE_server_sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
  fake_gNB_server_sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);

  fake_UE_addr.sin_family=AF_INET;
  fake_UE_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
  fake_UE_addr.sin_port=htons(FAKE_UE_PORT);

  fake_gNB_addr.sin_family=AF_INET;
  fake_gNB_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
  fake_gNB_addr.sin_port=htons(FAKE_gNB_PORT);

  fake_UE_server_addr.sin_family=AF_INET;
  fake_UE_server_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
  fake_UE_server_addr.sin_port=htons(FAKE_UE_SERVER_PORT);

  if(bind(fake_UE_server_sock,(struct sockaddr *)&fake_UE_server_addr,sizeof(fake_UE_server_addr))==-1) {
	  printf("Bind fake_UE_server_sock Error!\n");
    exit(2);
  }

  fake_gNB_server_addr.sin_family=AF_INET;
  fake_gNB_server_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
  fake_gNB_server_addr.sin_port=htons(FAKE_gNB_SERVER_PORT);
  if(bind(fake_gNB_server_sock,(struct sockaddr *)&fake_gNB_server_addr,sizeof(fake_gNB_server_addr))==-1) {
	  printf("Bind fake_gNB_server_sock Error!\n");
    exit(3);
  }

  pthread_t UE2gNB_proc, gNB2UE_proc;
  pthread_create(&UE2gNB_proc,NULL,worker,(void*)12);
  pthread_create(&gNB2UE_proc,NULL,worker,(void*)21);

  pthread_join(UE2gNB_proc, NULL);
  pthread_join(gNB2UE_proc, NULL);
  return 0;
}
