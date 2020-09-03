#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define TCP 1
#define UDP 2
#define ICMP 3
#define IP 4
#define ARP 5
#define ALL 6


void print_mac(struct ethhdr *p);
void parse_ip(char *buf, int flag);
void parse_arp(char *buf);

int menu(){
  int choose ;
  while( 1 ){
    system("clear");
    printf("\n");
    printf("\t**********************************\n");
    printf("\t*0 : 退出quit                    *\n");
    printf("\t*1 : 只抓取tcp包                 *\n");
    printf("\t*2 : 只抓取UDP包                 *\n");
    printf("\t*3 : 只抓取ICMP包                *\n");
    printf("\t*4 : 只抓取IP包                  *\n");
    printf("\t*5 : 只抓取ARP包                 *\n");
    printf("\t*6 : 抓取所有数据包ALL           *\n");
    printf("\t**********************************\n");

    printf("\t请输入想要抓取的数据包：");
    scanf("%d%*c", &choose);
    if(choose >= 0 && choose <= 6){
      break;
    }else{
      printf("\t输入有误，请重新输入!\n");
    }
  }
  return choose;
}

void do_quit() {
  printf("抓包结束，谢谢使用！\n");
  exit(0);          
}

void do_proc(int flag){
  if(fork() == 0){
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    
    int sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));    
    char buf[2000];    
    while ( 1  ) {    
      memset(buf, 0x00, sizeof(buf));    
      int r = read(sfd, buf, 2000);    
      if ( r <= 0   ) break;   
      struct ethhdr *peth = (struct ethhdr*)buf;

      if ( ntohs(peth->h_proto) == ETH_P_IP && flag != ARP  ) {//ETH_P_IP是0800的宏    
        struct iphdr *phdr = (struct iphdr*)(buf+sizeof(struct ethhdr));
        if(flag == IP || flag == ALL){
					print_mac(peth);                          
          //%#x格式的意思为在结果前边加上0x
          printf("Type:%#x\n", ntohs(peth->h_proto)); //将数据转换成本机字节序，否则会出错，以下类似
          parse_ip(buf+sizeof(struct ethhdr), flag);//偏移掉链路层帧头，以下类似
        }else if((flag == TCP || flag == ALL) && phdr->protocol == IPPROTO_TCP){
					print_mac(peth);                                                                                                                         
          printf("Type:%#x\n", ntohs(peth->h_proto));    
          parse_ip(buf+sizeof(struct ethhdr), flag);
        }else if((flag == UDP || flag == ALL) && phdr->protocol == IPPROTO_UDP){
					print_mac(peth);                                                                                                                         
          printf("Type:%#x\n", ntohs(peth->h_proto));    
          parse_ip(buf+sizeof(struct ethhdr), flag);
        }else if((flag == ICMP || flag == ALL) && phdr->protocol == IPPROTO_ICMP){
					print_mac(peth);                                                                                                                         
          printf("Type:%#x\n", ntohs(peth->h_proto));  
          parse_ip(buf+sizeof(struct ethhdr), flag);
        }
      } else if ( ntohs(peth->h_proto) == ETH_P_ARP && ( flag == ARP || flag == ALL )) {//ETH_P_ARP是0806的宏                           
        print_mac(peth);                                                                                               
        printf("Type:%#x\n", ntohs(peth->h_proto)); 
        parse_arp(buf+sizeof(struct ethhdr));//偏移掉链路层帧头                                                                           
      }
    }
  }else{
    wait(NULL);
  }
}


int main( void ) {
  sigset_t set;    
  sigemptyset(&set);    
  sigaddset(&set, SIGINT);    
  sigprocmask(SIG_BLOCK, &set, NULL);
  while(1){
    int cho = menu();
    if ( cho == 0 ){
      do_quit();
      break;
    }
    else{
      if(cho == 1)
        printf("抓取 TCP 包\n");
      if(cho == 2)    
        printf("抓取 UDP 包\n");
      if(cho == 3)    
        printf("抓取 ICMP 包\n");
      if(cho == 4)    
        printf("抓取 IP 包\n");
      if(cho == 5)    
        printf("抓取 ARP 包\n");
      if(cho == 6)    
        printf("抓取 ALL 包\n");
      do_proc(cho);
    }
  }
}

void print_mac(struct ethhdr *p) {
	printf("帧头[ 源MAC地址%02x:%02x:%02x:%02x:%02x:%02x", p->h_source[0], p->h_source[1], p->h_source[2],
							p->h_source[3], p->h_source[4], p->h_source[5]);
	printf(" <==> : 目的MAC地址%02x:%02x:%02x:%02x:%02x:%02x ]", p->h_dest[0], p->h_dest[1], p->h_dest[2],
							p->h_dest[3], p->h_dest[4], p->h_dest[5]);
}

void print_udp(char *buf) {
	struct udphdr *pt = (struct udphdr*)buf;
	printf("UDP头部[ 源端口号： %hu <===> 目的端口号： %hu ]", ntohs(pt->source), ntohs(pt->dest));
	printf("\n\n");
}

void print_icmp(char *buf) {
	struct icmphdr* icmph = (struct icmphdr*)buf;
  printf("ICMP头部[ 类型:%hd , 代码:%hd , 校验和:%d\n\n ]",icmph->type ,icmph->code ,icmph->checksum);
}
void print_tcp(char *buf) {
	struct tcphdr *pt = (struct tcphdr*)buf;
	printf("TCP头部[ 源端口：%hu 目的端口: %hu  序号seq : %u ", ntohs(pt->source), ntohs(pt->dest), ntohl(pt->seq));
	
	if ( pt->ack )
		printf("确认号ack_seq: %u", ntohl(pt->ack_seq));

	if ( pt->fin ) printf(" fin");
	if ( pt->syn ) printf(" syn");
	if ( pt->ack ) printf(" ack");
	printf("]");
	printf("\n\n");
}

void parse_ip(char *buf, int flag) {
	struct iphdr *phdr = (struct iphdr*)buf;
	struct in_addr ad;
  if ( phdr->protocol == IPPROTO_TCP && (flag == TCP || flag == IP || flag == ALL )) {
		ad.s_addr = phdr->saddr;    
    printf("\tIP头部[ 源IP地址：%s <==> ", inet_ntoa(ad));//inet_ntoa()函数可以直接将ip地址转换成对应字符串    
    ad.s_addr = phdr->daddr;    
    printf("目的IP地址：%s, 协议procotol: %hhd, 生存时间ttl:%hhu, 首部长度tot_len:%hu ]", inet_ntoa(ad), phdr->protocol, phdr->ttl, phdr->tot_len);    
    printf("\n\t\t");	
	  print_tcp(buf+sizeof(struct iphdr));
	} else if ( phdr->protocol == IPPROTO_UDP && (flag == UDP || flag == IP || flag == ALL )) {
		ad.s_addr = phdr->saddr;    
    printf("\tIP头部[ 源IP地址： %s <==> ", inet_ntoa(ad));//inet_ntoa()函数可以直接将ip地址转换成对应字符串    
    ad.s_addr = phdr->daddr;    
    printf("目的IP地址： %s, 协议procotol: %hhd, 生存时间ttl:%hhu, 首部长度tot_len:%hu ]", inet_ntoa(ad), phdr->protocol, phdr->ttl, phdr->tot_len);    
    printf("\n\t\t");		
    print_udp(buf+sizeof(struct iphdr));
	} else if ( phdr->protocol == IPPROTO_ICMP && (flag == ICMP || flag == IP || flag == ALL )) {
		ad.s_addr = phdr->saddr;    
    printf("\tIP头部[ 源IP地址：%s <==> ", inet_ntoa(ad));//inet_ntoa()函数可以直接将ip地址转换成对应字符串    
    ad.s_addr = phdr->daddr;    
    printf("目的IP地址： %s, 协议procotol: %hhd, 生存时间ttl:%hhu, 首部长度tot_len:%hu ]", inet_ntoa(ad), phdr->protocol, phdr->ttl, phdr->tot_len);    
    printf("\n\t\t");
    print_icmp(buf+sizeof(struct iphdr));
	}
}

void parse_arp(char *buf) {
  struct arphdr* arph = (struct arphdr*)buf;
	printf("\tARP头部[ 物理网络类型：%hd  协议类型：%hd 物理地址长度：%hhd 协议地址长度：%hhd 操作：%hu ]\n\n",
     ntohs(arph->ar_hrd), arph->ar_pro, arph->ar_hln, arph->ar_pln, ntohs(arph->ar_op));//操作数为1代表请求，2代表响应
}

