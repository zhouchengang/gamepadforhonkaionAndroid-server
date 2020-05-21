#define  _CRT_SECURE_NO_WARNINGS 
#include <stdio.h>    
#include <winsock2.h> 
#include <WS2tcpip.h>
#include <iostream>
#include <string>
#include "sha1.h"
#include "base64.h"
#pragma comment(lib,"ws2_32.lib") 

using namespace std;

string getString = "GET";
/*
	封装webSocket握手响应
*/
void getKey(char* request, string clientkey) {
	strcat(request, "HTTP/1.1 101 Switching Protocols\r\n");
	strcat(request, "Connection: upgrade\r\n");
	strcat(request, "Sec-WebSocket-Accept: ");
	string server_key = clientkey;
	server_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	SHA1  sha;
	unsigned int message_digest[5];
	sha.Reset();
	sha << server_key.c_str();
	sha.Result(message_digest);
	for (int i = 0; i < 5; i++) {
		message_digest[i] = htonl(message_digest[i]);
	}
	base64 base;
	server_key = base.base64_encode(reinterpret_cast<const unsigned char*>(message_digest), 20);
	server_key += "\r\n";
	strcat(request, server_key.c_str());
	strcat(request, "Upgrade: websocket\r\n\r\n");
}

/*给客户端发送数据也需要进行加密处理，就是保持通讯协议*/
void respondClient(SOCKET sockClient, byte charb[], int length, boolean finalFragment) {
	/*
		获取所需要发送数据的真实长度
		length 是真实的数据, 根据数据长度计算需要拼接验证数据的长度
		也就是说添加数据头
	*/
	int realDateLength;
	if (length < 126) {
		realDateLength = length + 2;
	}
	else if (length < 65536) {
		realDateLength = length + 4;
	}
	else {
		realDateLength = length + 10;
	}
	byte* buf;
	buf = (byte*)malloc(realDateLength);
	char* charbuf;
	charbuf = (char*)malloc(realDateLength);
	int first = 0x00;
	int tmp = 0;
	if (finalFragment) {
		// 数据一次性发送完毕
		first = first + 0x80;
		first = first + 0x1;
	}
	buf[0] = first;
	tmp = 1;
	unsigned int nuNum = (unsigned)length;
	if (length < 126) {
		buf[1] = length;
		tmp = 2;
	}
	else if (length < 65536) {
		buf[1] = 126;
		buf[2] = nuNum >> 8;
		buf[3] = length & 0xFF;
		tmp = 4;
	}
	else {
		//数据长度超过65536
		buf[1] = 127;
		buf[2] = 0;
		buf[3] = 0;
		buf[4] = 0;
		buf[5] = 0;
		buf[6] = nuNum >> 24;
		buf[7] = nuNum >> 16;
		buf[8] = nuNum >> 8;
		buf[9] = nuNum & 0xFF;
		tmp = 10;
	}
	for (int i = 0; i < length; i++) {
		buf[tmp + i] = charb[i];
	}
	// 内存拷贝 把需要发送的数据拷贝到临时内存区
	// 把buf里面的数据 从开始到 realDateLength 位置之间的数据拷贝到charbuf中 
	memcpy(charbuf, buf, realDateLength);
	// 发送数据
	send(sockClient, charbuf, realDateLength, 0);
}

/*获取key和协议*/
int requestInfo(SOCKET sockClient, char* request) {
	int result = -1;
	//存储握手请求数据
	char revData[2048];
	int ret = recv(sockClient, revData, strlen(revData), 0);
	string revDataString = revData;
	//cout << "接受到:" << revDataString << endl;
	// 判断握手请求中是否存在GET
	string::size_type idx;
	idx = revDataString.find(getString);
	if (idx == string::npos) {
		cout << "当前不是握手协议, 握手失败" << endl;
	}
	else {
		cout << "当前是握手协议, 开始握手" << endl;
		// 查找协议中的Sec-WebSocket-Key 字段
		int index = revDataString.find("Sec-WebSocket-Key");
		if (index > 0) {
			// 截取 Sec-WebSocket-Key 字段的内容
			string secWebSocketKeyString = revDataString.substr(index + 19, 24);
			// 进行Sec-WebSocket-Key字段加密, 加密后返回客户端, 完成握手动作
			getKey(request, secWebSocketKeyString);
			result = 1;
		}
		else {
			cout << "当前协议中不存在Sec-WebSocket-Key字段, 握手失败" << endl;
		}
	}
	return result;
}

/*发送协议*/
void respondInfo(SOCKET sockClient, char* request) {
	send(sockClient, request, strlen(request), 0);
}

void getClientInfo(SOCKET sClient, char clieninfo[])
{
	int point = 0;            //字节指针位置
	int tmppoint = 0;         //临时指针变量
	int byteArrayLength = sizeof(clieninfo);

	byte b[4096] = "";

	//转为字节来处理
	memcpy(b, clieninfo, 2048);
	//cout << "字节长度: " << end(b) - begin(b) << endl;


	//cout << "字节长度: " << end(b) - begin(b) << endl;
	for (int i = 0; i < 30; i++) {
		//cout << "字节" << i << ":" << b[i] << endl;
	}
	for (int i = 0; i <= 10; i++) {
		//printf("%d\t", b[i]);
	}
	//printf("\n");
	//取第一个字节
	//cout << "第一个字节:" << b[point] << endl;
	int first = b[point] & 0xFF;
	//printf("第一个：%d,%d,%d\n", point, b[point], first);
	byte opCode = (byte)(first & 0x0F);             //0000 1111 后四位为opCode 00001111
	if (opCode == 8) {
		//cout << "关闭" << endl;
		//cout << "opCode:" << opCode << endl;
		closesocket(sClient);
	}
	//取第二个字节
	first = b[++point];
	//负载长度
	int payloadLength = first & 0x7F;
	//printf("第二个：%d,[%d],%d\n", point, b[point], payloadLength);
	if (payloadLength == 126) {
		byte extended[2] = "";
		extended[0] = b[++point];
		extended[1] = b[++point];
		int shift = 0;
		payloadLength = 0;
		for (int i = 2 - 1; i >= 0; i--) {
			payloadLength = payloadLength + ((extended[i] & 0xFF) << shift);
			shift += 8;
		}
	}
	else if (payloadLength == 127) {
		byte extended[8] = "";
		tmppoint = ++point;     //保存临时指针
		point = --point;
		for (int i = 0; i < 8; i++) {
			extended[i] = b[tmppoint + i];
			point++;
		}
		int shift = 0;
		payloadLength = 0;
		for (int i = 8 - 1; i >= 0; i--) {
			payloadLength = payloadLength + ((extended[i] & 0xFF) << shift);
			shift += 8;
		}
	}
	//非126和127置回来
	if ((payloadLength != 126) || (payloadLength != 127)) {
		point = 1;
	}

	//cout << "负载长度:" << payloadLength << endl;
	//第三个字节，掩码
	byte mask[4] = "";
	tmppoint = ++point;
	//因为自增了一次，这里需要减掉
	point = --point;
	//取掩码值
	for (int i = 0; i < 4; i++) {
		mask[i] = b[tmppoint + i];
		point++;
		//printf("第三mask个：%d,[%d],%d\t\n", point, mask[i], payloadLength);
	}
	byte changeb[4096] = "";

	//内容的长度保留，循环里面已经被改变
	int length = payloadLength;
	int readThisFragment = 1;
	//通过掩码计算真实的数据
	while (payloadLength > 0) {
		int maskbyte = b[++point];
		int index = (readThisFragment - 1) % 4;
		maskbyte = maskbyte ^ (mask[index] & 0xFF);
		changeb[readThisFragment - 1] = (byte)maskbyte;
		//printf("内容：%d,[%d],%d\n", point, maskbyte, readThisFragment);
		payloadLength--;
		readThisFragment++;
	}
	//打印客户端的数据
	char charb[4096] = "";
	memcpy(charb, changeb, length);
	//cout << "length:" << length << endl;
	charb[length] = 0;
	//for (int i = 0; i < length; i++) {
	//	printf("%d\t", charb[i]);
	//}
	//printf("%d\n", 0);
	//cout << strlen(charb) << endl;
	string s = charb;
	
	//cout << "客户端数据:" << s << endl;

	int si = -1;
	try {
		si = stoi(s);
	}
	catch (std::invalid_argument&) {
		si = -1;
	}

	cout << "Received :"<<si<< endl;
	switch (si) {

	case 1:
		keybd_event('J', 0, 0, 0);
		break;
	case 2:
		keybd_event('I', 0, 0, 0);
		break;
	case 3:
		keybd_event('K', 0, 0, 0);
		break;
	case 4:
		keybd_event('U', 0, 0, 0);
		break;
	case 5:
		keybd_event('2', 0, 0, 0);
		break;
	case 6:
		keybd_event('1', 0, 0, 0);
		break;
	case 7:
		keybd_event(27, 0, 0, 0);
		break;
	case 8:
		mouse_event(MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
		break;
	case 9:
		keybd_event(192, 0, 0, 0);
		break;
	case 10:
		keybd_event('U', 0, 0, 0);
		break;
	case 11:
		keybd_event(108, 0, 0, 0);
		break;



	case 101:
		keybd_event('J', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 102:
		keybd_event('I', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 103:
		keybd_event('K', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 104:
		keybd_event('U', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 105:
		keybd_event('2', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 106:
		keybd_event('1', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 107:
		keybd_event(27, 0, KEYEVENTF_KEYUP, 0);
		break;
	case 108:
		break;
	case 109:
		keybd_event(192, 0, KEYEVENTF_KEYUP, 0);
		break;
	case 110:
		keybd_event('U', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 111:
		keybd_event(108, 0, KEYEVENTF_KEYUP, 0);
		break;


	case 200:
		keybd_event('W', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('D', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('S', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 201:
		keybd_event('W', 0, 0, 0);
		keybd_event('D', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('S', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 202:
		keybd_event('W', 0, 0, 0);
		keybd_event('D', 0, 0, 0);
		keybd_event('S', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 203:
		keybd_event('W', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('D', 0, 0, 0);
		keybd_event('S', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 204:
		keybd_event('W', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('D', 0, 0, 0);
		keybd_event('S', 0, 0, 0);
		keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 205:
		keybd_event('W', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('D', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('S', 0, 0, 0);
		keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 206:
		keybd_event('W', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('D', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('S', 0, 0, 0);
		keybd_event('A', 0, 0, 0);
		break;
	case 207:
		keybd_event('W', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('D', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('S', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('A', 0, 0, 0);
		break;
	case 208:
		keybd_event('W', 0, 0, 0);
		keybd_event('D', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('S', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('A', 0, 0, 0);
		break;








	case 300:
		keybd_event('N', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('E', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('M', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 301:
		keybd_event('N', 0, 0, 0);
		keybd_event('E', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('M', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 302:
		keybd_event('N', 0, 0, 0);
		keybd_event('E', 0, 0, 0);
		keybd_event('M', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 303:
		keybd_event('N', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('E', 0, 0, 0);
		keybd_event('M', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 304:
		keybd_event('N', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('E', 0, 0, 0);
		keybd_event('M', 0, 0, 0);
		keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 305:
		keybd_event('N', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('E', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('M', 0, 0, 0);
		keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
		break;
	case 306:
		keybd_event('N', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('E', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('M', 0, 0, 0);
		keybd_event('Q', 0, 0, 0);
		break;
	case 307:
		keybd_event('N', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('E', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('M', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('Q', 0, 0, 0);
		break;
	case 308:
		keybd_event('N', 0, 0, 0);
		keybd_event('E', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('M', 0, KEYEVENTF_KEYUP, 0);
		keybd_event('Q', 0, 0, 0);
		break;

	}






}


void responseInfo(SOCKET sClient)
{
	char message[] = "123456";
	byte test[30] = "";
	memcpy(test, message, strlen(message));
	respondClient(sClient, test, strlen(message), true);
}

// 专门处理套接字通讯的线程避免干扰主线程 建立新的链接
/*工作线程*/
void WorkThread(SOCKET sockClient) {
	char request[1024] = "";   //封装握手响应信息
	char clieninfo[2048] = ""; //握手后响应信息
	// 获取握手请求
	int result = requestInfo(sockClient, request);
	if (result > 0) {
		cout << "request:" << request << endl;
		// 握手响应
		int ret = send(sockClient, request, strlen(request), 0);
		if (ret > 0) {
			cout << "握手响应结果ret:" << ret << endl;
			while (true) {
				// 清空存储数组
				memset(clieninfo, '\0', sizeof(clieninfo));
				ret = recv(sockClient, clieninfo, 2048, 0);
				if (ret > 0) {
					// 解析客户端数据
					getClientInfo(sockClient, clieninfo);
					responseInfo(sockClient);
				}
				else {
					return;
					cout << "获取客户端数据失败" << endl;
				}
			}
		}
		else {
			cout << "握手响应失败, 关闭socket" << endl;
		}
	}
	// 关闭socket
	closesocket(sockClient);
}


/*
	初始化Socket创建 同时开启监听
	每次监听到连接之后 开启线程处理通讯
*/
void Initsocket(int port) {
	//初始化WSA windows自带的socket
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		cout << "WSAStartup调用失败!" << endl;
		return;
	}
	else {
		//创建服务端套接字  使用TCP协议
		SOCKET slisten = socket(AF_INET, SOCK_STREAM, 0);
		if (slisten == INVALID_SOCKET)
		{
			cout << "socket 创建失败" << endl;
			return;
		}
		else {
			//服务端需要绑定ip和端口
			sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_port = htons(port);
			sin.sin_addr.S_un.S_addr = INADDR_ANY; //监听任意的地址
			if (bind(slisten, (LPSOCKADDR)&sin, sizeof(sin)) == SOCKET_ERROR) //将服务端套接字与上面的ip和端口绑定 
			{
				cout << "套接字绑定失败" << endl;
				return;
			}
			else {
				//开始监听
				if (listen(slisten, 5) == SOCKET_ERROR)  //用listen（） 监听前面绑定好的slisten套接字 参数5的意思表示一次最多保持5条连接
				{
					cout << "套接字监听失败" << endl;
					return;
				}
				else {
					//循环接受数据
					sockaddr_in remoteAddr;
					int nAddrlen = sizeof(remoteAddr); //用于接受客户端地址
					// 开启循环等待连接, 连接成功之后开启线程处理连接之间的通讯
					while (true) {
						cout << "等待连接......" << endl;
						// 阻塞方法 每次获取到获取到一个链接后, 建立一个新的套接字, 之后这个链接的通讯都由这个套接字完成
						SOCKET sClient = accept(slisten, (SOCKADDR*)&remoteAddr, &nAddrlen); //和客户端 connect（）对应
						if (sClient == INVALID_SOCKET)
						{
							cout << "accept error !" << endl;

						}
						else {
							cout << "准备握手" << endl;
							//我这里起了一个线程来处理协议 
							HANDLE hThread1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, (LPVOID)sClient, 0, 0);
							if (hThread1 != NULL)
							{
								CloseHandle(hThread1);
							}
						}
					}
				}
			}
		}
	}
}

int main(int argc, char* argv[])

{
	int port = 8001;
	Initsocket(port);
	WSACleanup();
	return 0;
}
