#include <stdio.h>
#include <stdlib.h> 
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#define ICMP_PROTO 1
#define TCP_PROTO 6
#define FLAG_FIN 1
#define FLAG_SYN 2
#define FLAG_RST 4
#define FLAG_PSH 8
#define FLAG_ACK 16
#define FLAG_URG 32
#define MAX_HASH_KEY 255*8+65535*2

struct tcp_ip_unit *hash_map[MAX_HASH_KEY] = {NULL};
u_int active_sessions = 0;
u_int finished_sessions = 0;
u_int failure_sessions = 0;

struct tcp_ip_unit {
    struct tcp_ip_unit *next;
    u_short src_port;
    u_short dst_port;
    u_char src_addr[4];
    u_char dst_addr[4];
    u_char flags;
    u_char prev_flags;
    u_char cnt_push;
    u_char cnt_fin;
    u_char cnt_syn;
};


u_char
compare_addr_pair(const struct tcp_ip_unit *addr1, const struct tcp_ip_unit *addr2)
{
    int i;
    if((addr1->src_port != addr2->src_port || addr1->dst_port != addr2->dst_port) 
        && (addr1->src_port != addr2->dst_port || addr1->dst_port != addr2->src_port))return 0;
    for(i = 0; i < 4; i++) {
        if((addr1->src_addr[i] != addr2->src_addr[i] || addr1->dst_addr[i] != addr2->dst_addr[i]) 
            && (addr1->src_addr[i] != addr2->dst_addr[i] || addr1->dst_addr[i] != addr2->src_addr[i]))return 0;
    }
    return 1;
    
}

u_int
generate_hash_key(u_short src_port, u_short dst_port, u_char src_addr[], u_char dst_addr[])
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
delete_dead_session(u_int key,struct tcp_ip_unit *u)
{
    struct tcp_ip_unit *tmp = hash_map[key];
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
update_session_status(u_int key,struct tcp_ip_unit *u)
{
    if (u->flags == (FLAG_ACK)) {
        if(u->cnt_fin == 2) {
            finished_sessions++;
            if(active_sessions > 0) active_sessions--;  
            u->cnt_fin = 0;
            delete_dead_session(key,u);
            return;
        }
        if(u->prev_flags == (FLAG_SYN|FLAG_ACK)) {
            active_sessions++;
            u->cnt_syn = 0;
        }
    }
    else if(u->flags == (FLAG_FIN | FLAG_ACK))
        u->cnt_fin++;
    else if(u->flags == (FLAG_PSH | FLAG_ACK)) {
       if(!u->cnt_push++)active_sessions++;
    }
    else if (u->flags == FLAG_SYN) {
        u->cnt_syn++;
        if(u->cnt_syn > 3) {
            failure_sessions++;
            u->cnt_syn = 0;
            delete_dead_session(key,u);
        }
    }
}

struct tcp_ip_unit*
allocate_tcp_ip_unit(const struct tcp_ip_unit *u)
{
    struct tcp_ip_unit *u_tmp = malloc(sizeof(struct tcp_ip_unit));
    if (u_tmp == NULL) {
        fprintf(stderr,"Error allocate memory\n");
        exit(1);
    }
    u_tmp->src_port = u->src_port;
    u_tmp->dst_port = u->dst_port;
    u_tmp->flags = u_tmp->prev_flags = u->flags;
    memcpy(u_tmp->src_addr,u->src_addr,4);
    memcpy(u_tmp->dst_addr,u->dst_addr,4);
    u_tmp->next = NULL;
    u_tmp->cnt_fin = 0;
    u_tmp->cnt_syn = 0;
    u_tmp->cnt_push = 0;
    return u_tmp;

}


u_char
check_by_hash_key(u_int key,const struct tcp_ip_unit *u)
{
    if(!hash_map[key]){
       hash_map[key] = allocate_tcp_ip_unit(u);
       update_session_status(key,hash_map[key]);
       return 0;
    } 
       struct tcp_ip_unit *head = hash_map[key]; 
       while(!compare_addr_pair(head,u)) {
          if(head->next == NULL) {
             head->next = allocate_tcp_ip_unit(u);
             update_session_status(key,head->next);
             return 0;
          }
          head = head->next;
       }
       head->prev_flags = head->flags;
       head->flags = u->flags;
       update_session_status(key,head);
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
    u_char ip_header_length = (data[begin_ip_header] & 15)*4;
    if (proto == ICMP_PROTO) {
        u_char icmp_type = data[begin_ip_header+ip_header_length];
        if(icmp_type == 3)
            failure_sessions++;
    }
    if (proto != TCP_PROTO)return;

    u_short begin_tcp_header = begin_ip_header + ip_header_length;
    u_char tcp_flags = data[begin_tcp_header+13];
    u_short *port_src = (u_short*)&data[begin_tcp_header];
    u_short *port_dest = (u_short*)&data[begin_tcp_header+2];
    u_int tcp_ip_hash_key = generate_hash_key(*port_src,*port_dest,src_addr,dest_addr);
    struct tcp_ip_unit u;
    u.src_port =  *port_src;
    u.dst_port =  *port_dest;
    u.flags = u.prev_flags = tcp_flags;
    memcpy(u.src_addr,src_addr,4);
    memcpy(u.dst_addr,dest_addr,4);
    u.next = NULL;
    u.cnt_fin = 0;
    u.cnt_syn = 0;
    u.cnt_push = 0;
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

