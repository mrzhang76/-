#include<stdio.h>
#include<winsock2.h>
#include<time.h>
#pragma commment(lib,"ws2_32.lib")

int main(void){
	WSADATA wsa;
	WSAStartup(WINSOCK_VERSION,&wsa);	//初始化WS2_32.DLL
 
	SOCKET serversoc;
	SOCKET clientsoc;
	SOCKADDR_IN serveraddr;
	SOCKADDR_IN clientaddr;
	int client_len = sizeof(clientaddr);
	int server_len = sizeof(serveraddr);
	char *Send_data;
	int Send_len;
	char Recv_buf[64];
	int result;
	time_t nowtime;
 
	//命名协议，IP，端口
    serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(1233);
	serveraddr.sin_addr.s_addr =  inet_addr("192.168.2.17");
 
	//创建socket
	serversoc = socket(AF_INET,SOCK_DGRAM,0);
	
 
	//绑定socket
	result=bind(serversoc, (SOCKADDR *)&serveraddr, server_len);
	if(result==SOCKET_ERROR)
	{
		printf("socket bind failed!\n");
		closesocket(serversoc);
		return -1;
	}
 
	printf("Server is running.....\n");
 
	clientsoc = socket(AF_INET,SOCK_DGRAM,0);
	while(1)
	{   
		//接收数据
		result = recvfrom(serversoc,Recv_buf,64,0,(SOCKADDR *)&clientaddr,&client_len);
		if(result >= 0)
		{
			Recv_buf[result]= 0;
			printf("Server Received Data:  %s \n",Recv_buf);
			printf("Server is running.....\n");
		}
	}
 
	closesocket(serversoc);
	WSACleanup();
	return 0;

}
