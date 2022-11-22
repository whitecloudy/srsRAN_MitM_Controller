#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <mutex>

#include "src/ue_packet_handler.h"
#include "src/gnb_packet_handler.h"


#define LOOPBACK_IP ("127.123.123.24")

#define FAKE_UE_PORT (8081)
#define FAKE_gNB_PORT (9091)
#define FAKE_UE_SERVER_PORT (8080)
#define FAKE_gNB_SERVER_PORT (9090)

enum RELAY_DIR 
{
  FROM_FAKE_UE,
  FROM_FAKE_gNB
};

struct sockaddr_in fake_UE_server_addr;
struct sockaddr_in fake_gNB_server_addr;
struct sockaddr_in fake_UE_addr, fake_gNB_addr;

struct sockaddr_in backend_addr;

int fake_UE_server_sock;
int fake_gNB_server_sock;

int backend_sock;

int msg_count = 6;
std::string packet2send = "[";

void* worker(void *arg) {
  static std::mutex m;
  printf("Thread Created!\n");

  int *fake_src_sock, *fake_dst_sock;
  struct sockaddr_in *fake_src_addr, *fake_dst_addr;

  enum RELAY_DIR dir_v = *(enum RELAY_DIR *)arg;

  if (dir_v==FROM_FAKE_UE) {
    fake_src_sock=&fake_UE_server_sock; 
    fake_dst_sock=&fake_gNB_server_sock;

    fake_src_addr=&fake_UE_addr;
    fake_dst_addr=&fake_gNB_addr;
  }
  else if (dir_v==FROM_FAKE_gNB) { /*(uintptr_t)arg==21*/
    fake_src_sock=&fake_gNB_server_sock; 
    fake_dst_sock=&fake_UE_server_sock;

    fake_src_addr=&fake_gNB_addr;
    fake_dst_addr=&fake_UE_addr;
  }else {
    std::cerr << "Wrong argument to worker" << std::endl;
    return NULL;
  }

  while(1) {
    uint8_t buf[65535];
    socklen_t sn=sizeof(*fake_src_addr);
    asn1::json_writer * packet_json_p = NULL;
    int n=recvfrom(*fake_src_sock,buf,sizeof(buf),0,(struct sockaddr *)fake_src_addr,&sn);
    //int n=recv(*fake_src_sock,buf,sizeof(buf),0);
    if(dir_v == FROM_FAKE_UE){  //Target gNB's packet is arrive here
      packet_json_p = gNB::decode_packet(buf, n);
    }else if(dir_v ==FROM_FAKE_gNB){  //Target UE's packet is arrive here
      packet_json_p = UE::decode_packet(buf, n);
    }else{
      std::cerr << "Error: Undefined dir_v!"<< std::endl;
    }

    //std::cout << packet_json_p->to_string() << std::endl;
    m.lock();
    if(msg_count > 0)
    {
      std::cout << msg_count << std::endl;
      if(msg_count != 6)
        packet2send += ',';
      
      std::string str = packet_json_p->to_string();

      packet2send += str.substr(1, str.length()-2);


      msg_count -= 1;

      if(msg_count == 0)
      {
        msg_count -= 1;
        packet2send += ']';
        //std::cout << packet2send << std::endl;
        //std::cout << "hello?" << std::endl;
        std::cout << packet2send << std::endl;
        
        sendto(backend_sock, packet2send.c_str(), packet2send.length() ,0,(struct sockaddr *)&backend_addr,sizeof(backend_addr));
      }
    }
    m.unlock();
    
    delete packet_json_p;

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
  backend_sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);

  fake_UE_addr.sin_family=AF_INET;
  fake_UE_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
  fake_UE_addr.sin_port=htons(FAKE_UE_PORT);

  fake_gNB_addr.sin_family=AF_INET;
  fake_gNB_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
  fake_gNB_addr.sin_port=htons(FAKE_gNB_PORT);

  fake_UE_server_addr.sin_family=AF_INET;
  fake_UE_server_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
  fake_UE_server_addr.sin_port=htons(FAKE_UE_SERVER_PORT);

  backend_addr.sin_family=AF_INET;
  backend_addr.sin_addr.s_addr = inet_addr("127.0.0.4");
  backend_addr.sin_port = htons(8000);

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
  enum RELAY_DIR argv1 = FROM_FAKE_UE;
  enum RELAY_DIR argv2 = FROM_FAKE_gNB;
  pthread_create(&UE2gNB_proc, NULL, worker, (void*)(&argv1));
  pthread_create(&gNB2UE_proc, NULL, worker, (void*)(&argv2));

  pthread_join(UE2gNB_proc, NULL);
  pthread_join(gNB2UE_proc, NULL);
  return 0;
}
