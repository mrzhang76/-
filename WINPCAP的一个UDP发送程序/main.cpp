#define WIN32  
#define HAVE_REMOTE //解决版本不同的问题，此问题导致找不到pcap_open
#define _CRT_SECURE_NO_WARNINGS  //关闭安全检测
#include"stdlib.h"
#include"stdio.h"
#include "pcap.h"
#include "remote-ext.h" //解决版本不同的问题，此问题导致找不到pcap_open
#include"main.h"

pcap_t* choose_pcap(void);
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
int send_packet(pcap_t* adhandle);

int  main(void){
    printf("please choose pcap\n");
    pcap_t* adhandle;
    char packet[100] = {0};
    if (adhandle = choose_pcap()) 
        printf("choose pcap success\n");
    else
        return -1;

    if (send_packet(adhandle))
        printf("send packet success\n");
    else
        return -1;
    return 0;
}

pcap_t* choose_pcap(void) {
    pcap_if_t* alldevs, * d;
    int i = 0;
    int inum = 0 ;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr, "Error inpcap_findalldevs: %s\n", errbuf);
        exit;
    }

    for (d = alldevs; d; d = d->next){
        printf("%d. %s", ++i, d->name);
        if (d->description)  printf(" (%s)\n", d->description);
        else  printf(" (Nodescription available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Makesure WinPcap is installed.\n");
        exit;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        exit;
    }

    /* 跳转到选中的适配器 */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* 打开设备 */
    if ((adhandle = pcap_open(d->name,          // 设备名
        65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
        1000,             // 读取超时时间
        NULL,             // 远程机器验证
        errbuf            // 错误缓冲池
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        exit;
    }
    
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);

    /* 返回设备 */
    return adhandle;
}

int send_packet(pcap_t* adhandle) {
    char buffer[100] = { 0 };//建立缓冲区
    char buffer1[64] = { 0 };
    ether_header* pether_header = (ether_header*)buffer;                                //以太网数据报头
    ip_header* pip_header = (ip_header*)(buffer + sizeof(ether_header));                //IP数据报头
    udphdr* pudp_header = (udphdr*)(buffer + sizeof(ether_header) + sizeof(ip_header));//UDP数据报头
    char* data = (char*)(buffer + sizeof(ether_header) + sizeof(ip_header) + sizeof(pudp_header)); //数据
    

    //设置 target_ip,target_mac,source_ip,source_mac , data
    char T_IP[20] = { 0 }, T_MAC[50] = { 0 }, S_IP[20] = { 0 }, S_MAC[50] = { 0 }, TEXT[30] = {0};
    printf("please enter information before send UDP\n");
    printf("set target IP:(*.*.*.*)\n");
    scanf("%s", &T_IP);
    printf("set target MAC:(1:1:1:1:1:1)\n");
    scanf("%02X%02X%02X%02X%02X%02X", &pether_header->ether_dhost[0], 
                              &pether_header->ether_dhost[1], 
                               &pether_header->ether_dhost[2], 
                               &pether_header->ether_dhost[3], 
                               &pether_header->ether_dhost[4], 
                               &pether_header->ether_dhost[5]);

    printf("set source IP:(*.*.*.*)\n");
    scanf("%s", &S_IP);
    printf("set source MAC:(1:1:1:1:1:1)\n");
    scanf("%02X%02X%02X%02X%02X%02X", &pether_header->ether_shost[0],
                              &pether_header->ether_shost[1],
                              &pether_header->ether_shost[2],
                              &pether_header->ether_shost[3],
                              &pether_header->ether_shost[4],
                              &pether_header->ether_shost[5]);

    printf("set data\n");
    scanf("%s", &TEXT);
    printf("Your information:\ntarget IP:%s\nsource IP:%s\nData:%s\n", T_IP, S_IP, TEXT);
    memcpy(data, (void*)TEXT, sizeof(TEXT));

    printf("target MAC:");
    for (int i = 0; i < 6; i++) {
        printf(":%02X", pether_header->ether_dhost[i]);
    }
    printf("\nsource MAC:");
    for (int i = 0; i < 6; i++) {
        printf(":%02X", pether_header->ether_shost[i]);
    }

    



    //构建以太网数据报头
    

    //设定协议
    pether_header->ether_type = htons(0x0800); 
    
    ////////////////////////////////////////

    //构建IP数据报头
    pip_header->version = 4 ;                   //IP_veersion
    pip_header->ihl = sizeof(ip_header) / 4;    //IP_header_length
    pip_header->tos = 0;                        //Type_of_service
    pip_header->tot_len = htons(sizeof(buffer) - sizeof(ether_header));     //Total_length
    pip_header->id = htons(0x1000);             //Identification
    pip_header->frag_off = htons(0);            //Fragment_offset
    pip_header->ttl = 0x80;                     //Time_to_live
    pip_header->protocol = IPPROTO_UDP;          //Protocol_type
    inet_pton(AF_INET,S_IP,&pip_header->saddr);  //Source_adress
    inet_pton(AF_INET, T_IP, &pip_header->daddr);//Destination_adress
    pip_header->check = in_cksum((u_int16_t*)pip_header, sizeof(ip_header));    //Check_sum
    
    if ((sizeof(ip_header) % 4) != 0){  //Check
        printf("[IP Header error]/n");
        return-1;
    }

    ////////////////////////////////////////

    //构建UDP数据报头
    pudp_header->dest = htons(1233);    //Target_port
    pudp_header->source = htons(1234);  //Source_port
    pudp_header->len = htons(sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header));//UDP_length
    pudp_header->checkl = 0;            //Checknum
    
    //构建伪UDP首部
    char buffer2[64] = { 0 }; //建立缓冲区2
    Psd_Header* psd = (Psd_Header*)buffer2;
    inet_pton(AF_INET, S_IP, &psd->sourceip);
    inet_pton(AF_INET, T_IP, &psd->destip);
    psd->ptcl = IPPROTO_UDP;
    psd->plen = htons(sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header));
    psd->mbz = 0;

    memcpy(buffer2 + sizeof(Psd_Header), (void*)pudp_header, sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header));
  
    pudp_header->checkl = in_cksum((u_int16_t*)buffer2,sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header) + sizeof(Psd_Header));
    
    if (pcap_sendpacket(adhandle, (const u_char*)buffer, 100 /* size */) != 0)
    {
        fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adhandle));
        return-1;
    }
    else {
        return 1;
    }
   

    return 1;
}







