#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "encry_des.h"

char * if_name = "ens33";//默认情况下接口端口名为ens33
int local_ip = 0;//直接记录32位本地IP地址的网络字节序，只用于比较
int full_encry = 0;//默认情况会加密所有从本机发出的IP包

static int fd;//使用netfilter_queue会使用到的变量
static struct nfq_handle *h;//使用netfilter_queue会使用到的变量
static struct nfq_q_handle *qh;//使用netfilter_queue会使用到的变量
static struct nfnl_handle *nh;//使用netfilter_queue会使用到的变量


int get_local_ip(char *);
void tcp_encry(unsigned char *,int *,int );
static void set_tcp_checksum1(struct iphdr*);

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
struct nfq_data *nfa, void *data)
//回调函数
{
	int id = 0;//IP包在队列中的序号
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *pdata = NULL;
	int pdata_len, iphdr_size;
	char srcstr[32], deststr[32];
	struct iphdr *piphdr;

//返回数据包nf头文件(队列ID)	
	ph = nfq_get_msg_packet_hdr(nfa);
	if(ph == NULL)
		return 1;
	id = ntohl(ph ->packet_id);

//获取IP层发来的报文
	pdata_len = nfq_get_payload(nfa, (unsigned char **)&pdata);
	if (pdata != NULL)
		piphdr = (struct iphdr *) pdata;//转换为IP头指针，获得IP头部
	else
		return 1;
	iphdr_size = piphdr->ihl << 2;//ip包头部长度

//将IP头部中的源地址和目的地至转化为点分式的字符串格式，供输出显示	
	inet_ntop(AF_INET, &(piphdr->saddr), srcstr, 32);
	inet_ntop(AF_INET, &(piphdr->daddr), deststr, 32);
	printf("get a packet: %s -> %s\n", srcstr, deststr);

	if(piphdr->saddr == local_ip)
	{
		printf("The packet is locally generated. Jump to encryption program.\n");
		if(piphdr->protocol == 6)//tcp报文
		{
			tcp_encry(pdata, &pdata_len, iphdr_size);
			set_tcp_checksum1(piphdr);
			return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
		}	
	}
/*		else if(piphdr->protocol == 17)//UDP报文
		{
			udp_entry(pdata, pdata_len, iphdr_size);
			return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
		}
	}

	if(piphdr->daddr == local_ip)
	{
		printf("The packet is sent to local. Jump to decryption program.\n");
		if(piphdr->protocol == 6)//tcp报文
		{
			tcp_decry(pdata, pdata_len, iphdr_size);
			return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
		}	
		else if(piphdr->protocol == 17)//UDP报文
		{
			udp_detry(pdata, pdata_len, iphdr_size);
			return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
		}
	}
*/
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}


int main(int argc, char **argv)
{ 
    char buf[1600] __attribute__((aligned));
    int length;
	
	local_ip = get_local_ip(if_name);
	
//	opening library handle
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

//	unbinding existing nf_queue handler for AF_INET (if any) 解除绑定
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "already nfq_unbind_pf()\n");
		exit(1);
	}

//	binding nfnetlink_queue as nf_queue handler for AF_INET 重新绑定协议簇
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

//	选择处理队列号以及设置回调函数
	qh = nfq_create_queue(h,0, &callback, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

//	设置参数模式（返回数据包）
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);
   	while(1)
    	{
		length=recv(fd,buf,1600,0);//此处完成收包
		nfq_handle_packet(h, buf,length);//完成发包的真正函数
	}
	nfq_destroy_queue(qh);
	nfq_close(h);
	exit(0);
}


//得到本地IP地址的32位int型数据,只用于比较
int get_local_ip(char * ifname)
{
    int inet_sock;
    struct ifreq ifr;
	int *temp;

//初始化套接字以及设置结构体ifreq
    inet_sock = socket(AF_INET, SOCK_DGRAM, 0); 

    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    memcpy(ifr.ifr_name, ifname, strlen(ifname));

    if(0 != ioctl(inet_sock, SIOCGIFADDR, &ifr)) //申请得到IP地址
    {   
        perror("ioctl error");
        return -1;
    }

//得到32位的ip地址数据
    temp = (unsigned int *)&(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr);      

    close(inet_sock);

    return *temp;
}


//针对ｔｃｐ协议的加密,传入参数为ＩＰ包负载，负载长度和ＩＰ头部大小
void tcp_encry(unsigned char *pdata, int *pdata_len, int iphdr_size)
{
	struct tcphdr *tcp_hdr;
	int tcphdr_size;
	int content_len;

//获得ＴＣＰ头部
	tcp_hdr = (struct tcphdr *)(pdata + iphdr_size);
	tcphdr_size = (tcp_hdr->doff) << 2;
	content_len = *pdata_len - iphdr_size - tcphdr_size;
	unsigned char *a = pdata + iphdr_size + tcphdr_size;

	if(content_len > 0)
	{
		content_len = des_encry(a, content_len);
		*pdata_len = content_len + iphdr_size + tcphdr_size;	
	}
}

static u_int16_t checksum(u_int32_t init, u_int8_t *addr, size_t count){ 
    /* Compute Internet Checksum for "count" bytes * beginning at location "addr". */ 
    u_int32_t sum = init; 

    while( count > 1 ) { 
        /* This is the inner loop */
        sum += ntohs(* (u_int16_t*) addr);
        addr += 2;
        count -= 2;
    } /* Add left-over byte, if any */
    if( count > 0 )
        sum += ntohs(* (u_int8_t*) addr); /* Fold 32-bit sum to 16 bits */ 
    while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16); 
    return (u_int16_t)~sum;
} 
static u_int16_t tcp_checksum2(struct iphdr* iphdrp, struct tcphdr* tcphdrp){ 
    size_t tcplen = ntohs(iphdrp->tot_len) - (iphdrp->ihl<<2); 
    u_int32_t cksum = 0;

    cksum += ntohs((iphdrp->saddr >> 16) & 0x0000ffff);
    cksum += ntohs(iphdrp->saddr & 0x0000ffff);
    cksum += ntohs((iphdrp->daddr >> 16) & 0x0000ffff);
    cksum += ntohs(iphdrp->daddr & 0x0000ffff);
    cksum += iphdrp->protocol & 0x00ff;
    cksum += tcplen; 
    return checksum(cksum, (u_int8_t*)tcphdrp, tcplen);
} 

static u_int16_t tcp_checksum1(struct iphdr* iphdrp){ 
    struct tcphdr *tcphdrp = (struct tcphdr*)((u_int8_t*)iphdrp + (iphdrp->ihl<<2)); 
    return tcp_checksum2(iphdrp, tcphdrp);
} 
static void set_tcp_checksum2(struct iphdr* iphdrp, struct tcphdr* tcphdrp){
    tcphdrp->check = 0;
    tcphdrp->check = htons(tcp_checksum2(iphdrp, tcphdrp));
} 
static void set_tcp_checksum1(struct iphdr* iphdrp){ 
    struct tcphdr *tcphdrp = (struct tcphdr*)((u_int8_t*)iphdrp + (iphdrp->ihl<<2));
    set_tcp_checksum2(iphdrp, tcphdrp);
}
