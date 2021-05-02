#include <stdio.h>
#include <stdlib.h> 
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#define TCP_PROTO 6
#define FLAG_FIN 1
#define FLAG_SYN 2
#define FLAG_RST 4
#define FLAG_PSH 8
#define FLAG_ACK 16
#define MAX_HASH_KEY 255*8+65535*2

struct tcp_ip *hash_map[MAX_HASH_KEY] = {NULL};
u_int active_sessions = 0;
u_int finished_sessions = 0;
u_int failure_sessions = 0;

struct tcp_ip {
    u_short src_port;
    u_short dst_port;
    u_char src_addr[4];
    u_char dst_addr[4];
    u_char state;
    struct tcp_ip *next; //Связный список коллизий
};


u_char
compare_addr_pair(const struct tcp_ip *addr1, const struct tcp_ip *addr2)
{
    int i;
    if((addr1->src_port != addr2->src_port) && (addr1->src_port != addr2->dst_port))return 0;
    if((addr1->dst_port != addr2->src_port) && (addr1->dst_port != addr2->dst_port))return 0;
    for(i = 0; i < 4; i++) {
        if((addr1->src_addr[i] != addr2->src_addr[i]) && (addr1->src_addr[i] != addr2->dst_addr[i]))return 0;
        if((addr1->dst_addr[i] != addr2->dst_addr[i]) && (addr1->dst_addr[i] != addr2->src_addr[i]))return 0;
    }
    return 1;
    
}

u_int
make_hash_tcpip(u_short src_port, u_short dst_port, u_char src_addr[], u_char dst_addr[])
{
    u_int r = 0;
    int i;
    r += src_port;
    r += dst_port;
    for(i = 0; i < 4; i++) {
       r += src_addr[i];
       r += dst_addr[i];
    }
    return r;  
}

void
delete_session(u_int key,struct tcp_ip *u)
{
    struct tcp_ip *tmp = hash_map[key];
    if (tmp == u) {
        free(u);
        hash_map[key] = NULL;
        return;
    }
    while(tmp->next != u)tmp=tmp->next;
    tmp->next = u->next;
    free(u);  
      
}

void
check_sessions(u_int key,struct tcp_ip *u)
{
    if(u->state & FLAG_PSH || u->state & FLAG_SYN) {
       active_sessions++;
       return;
    }
    else if(u->state == (FLAG_FIN | FLAG_ACK))
       finished_sessions++;
    else if(u->state == FLAG_RST)
       failure_sessions++;
    delete_session(key,u);

}

struct tcp_ip*
allocate_tcpip_unit(const struct tcp_ip *u)
{
    struct tcp_ip *u_tmp = malloc(sizeof(struct tcp_ip));
    if (u_tmp == NULL) {
        fprintf(stderr,"Error allocate memory\n");
        exit(1);
    }
    u_tmp->src_port =  u->src_port;
    u_tmp->dst_port =  u->dst_port;
    u_tmp->state = u->state;
    memcpy(u_tmp->src_addr,u->src_addr,4);
    memcpy(u_tmp->dst_addr,u->dst_addr,4);
    u_tmp->next = NULL;
    return u_tmp;

}

u_char
check_by_hash_key(u_int key,const struct tcp_ip *u)
{
    if(!hash_map[key]){
       hash_map[key] = allocate_tcpip_unit(u);
       check_sessions(key,hash_map[key]);
       return 0;
    } 
       struct tcp_ip *head = hash_map[key];
       while(!compare_addr_pair(head,u)) {
          if(head->next == NULL) {
             head->next = allocate_tcpip_unit(u);
             check_sessions(key,head->next);
             return 0;
          }
          head = head->next;
       }
       if (u->state == (FLAG_FIN | FLAG_ACK)) {
            finished_sessions++;
            if(active_sessions > 0) active_sessions--;
       } 
       else if(u->state == FLAG_RST) {
          if(active_sessions > 0) active_sessions--;
          failure_sessions++;         
       }
    return 0;
}



void
disp_tcp_ip_data(u_char *user,const struct pcap_pkthdr *hdr,const u_char *data)
{
    
    u_short begin_ip_header = 14;
    u_char *src_addr = &data[begin_ip_header+12];
    u_char *dest_addr = &data[begin_ip_header+16];
    u_short *ip_packet_len = (u_short*)&data[begin_ip_header+2];
    u_char proto = data[begin_ip_header+9];
    if(proto != TCP_PROTO)return;
    u_char ip_header_length = (data[begin_ip_header] & 15)*4;
    u_short begin_tcp_header = begin_ip_header + ip_header_length;
    u_char tcp_flags = data[begin_tcp_header+13];
    u_short *port_src = (u_short*)&data[begin_tcp_header];
    u_short *port_dest = (u_short*)&data[begin_tcp_header+2];
    u_int tcp_ip_hash_key = make_hash_tcpip(*port_src,*port_dest,src_addr,dest_addr);
    struct tcp_ip u;
    u.src_port =  *port_src;
    u.dst_port =  *port_dest;
    u.state = tcp_flags;
    memcpy(u.src_addr,src_addr,4);
    memcpy(u.dst_addr,dest_addr,4);
    u.next = NULL;
    check_by_hash_key(tcp_ip_hash_key,&u);
    #ifdef DEBUG_MODE
    printf("src port %d  dest port %d   tcpip hash = %d  packet len = %d FLAGS: ",ntohs(*port_src),ntohs(*port_dest),tcp_ip_hash_key,ntohs(*ip_packet_len)-40);
    if(tcp_flags & FLAG_FIN)printf("FIN ");
    if(tcp_flags & FLAG_SYN)printf("SYN ");
    if(tcp_flags & FLAG_RST)printf("RST ");
    if(tcp_flags & FLAG_PSH)printf("PSH ");
    if(tcp_flags & FLAG_ACK)printf("ACK");
    printf("\n");
    #endif

}

int 
main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fp;
    if(argc != 2) {
        fprintf(stderr,"Error! to run program: %s <filename pcap>\n",argv[0]);
        return 1;
    }
    fp = pcap_open_offline(argv[1],errbuf);
    if(fp == NULL) {
        fprintf(stderr, "Couldn't open file: %s\n",argv[1]);
        return 1;
    }
    if (pcap_dispatch(fp, 0, disp_tcp_ip_data, (u_char *)0) < 0) {
        fprintf(stderr,"Error reading packets\n");
        return 1;

    }
    printf("Active sessions: %d\t Finished sessions: %d\t Failure sessions: %d\n",active_sessions,finished_sessions,failure_sessions);
    return 0;
}

