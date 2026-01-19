#include <iostream>
#include <winsock2.h>
#include "protocol.h"
#include <cstdio>
#include <string>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// 密码设置
const char *LOW_LEVEL_PASS = "123456";    // 低级密码
const char *HIGH_LEVEL_PASS = "admin888"; // 高级密码
// 【修改】DES密钥必须是8位 (或者前8位有效)
const char *DES_KEY = "12345678";

class Server {
	private:
		SOCKET serverSocket, clientSocket;
		bool isLowAuth = false;
		bool isHighAuth = false;
		//文件传输相关的状态变量
		FILE *fpUpload = nullptr;      // 当前正在写入的文件指针
		long long fileSizeExpected = 0; // 预计接收的总大小
		long long fileSizeReceived = 0; // 当前已接收的大小

	public:
		void Start(int port) {
			WSADATA wsaData;
			WSAStartup(MAKEWORD(2, 2), &wsaData);

			serverSocket = socket(AF_INET, SOCK_STREAM, 0);
			sockaddr_in serverAddr;
			serverAddr.sin_family = AF_INET;
			serverAddr.sin_port = htons(port);
			serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

			if (bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
				cout << "绑定端口失败。" << endl;
				return;
			}
			listen(serverSocket, 1);
			cout << "[服务端] 启动监听 127.0.0.1:" << port << endl;

			while (true) {
				sockaddr_in clientAddr;
				int len = sizeof(clientAddr);
				cout << "\n[等待连接]..." << endl;
				clientSocket = accept(serverSocket, (sockaddr *)&clientAddr, &len);

				if (clientSocket == INVALID_SOCKET) {
					continue;
				}
				cout << "[服务端] 客户端已连接！" << endl;

				// 每次新连接，重置权限
				isLowAuth = false;
				isHighAuth = false;

				HandleClient();

				closesocket(clientSocket);
				cout << "[服务端] 客户端已断开。" << endl;
			}
		}

		void HandleClient() {
			DataPacket packet;
			// 确保每次新客户端连接时，文件指针是空的
			if (fpUpload) {
				fclose(fpUpload);
				fpUpload = nullptr;
			}
			while (recv(clientSocket, (char *)&packet, sizeof(DataPacket), 0) > 0) {
				DataPacket response;
				response.type = MSG_RESPONSE;
				memset(response.payload, 0, sizeof(response.payload));
				response.dataLength = 0; // 初始化

				switch (packet.type) {
					case MSG_LOGIN_LOW:
						if (strcmp(packet.payload, LOW_LEVEL_PASS) == 0) {
							isLowAuth = true;
							strcpy(response.payload, "[OK] 低级权限验证成功！");
						} else {
							strcpy(response.payload, "[ERR] 低级密码错误！");
						}
						break;

					case MSG_LOGIN_HIGH:
						if (!isLowAuth) {
							strcpy(response.payload, "[ERR] 错误：请先通过低级权限验证！");
						} else {
							// 解密前打印客户端传的密文（16进制）
							cout << "[服务端] 收到的密文（16进制）：";
							for (int i = 0; i < strlen(packet.payload); i++) {
								printf("%02X ", (unsigned char)packet.payload[i]);
							}
							cout << endl;
							char decryptedPass[1024] = {0};
							// 【关键修改】使用 packet.dataLength 进行解密
							DES_Decrypt(packet.payload, packet.dataLength, decryptedPass, DES_KEY);

							// 调试输出（可选）
							// cout << "收到密文长度: " << packet.dataLength << " 解密后: " << decryptedPass << endl;

							if (strcmp(decryptedPass, HIGH_LEVEL_PASS) == 0) {
								isHighAuth = true;
								strcpy(response.payload, "[OK] 高级权限验证成功！");
							} else {
								strcpy(response.payload, "[ERR] 高级密码错误！");
							}
						}
						break;

					case MSG_COMMAND:
						if (!isLowAuth) {
							strcpy(response.payload, "权限不足：未登录。");
						} else {
							cout << "[执行命令] " << packet.payload << endl;
							string cmd = string(packet.payload) + " 2>&1";
							FILE *pipe = _popen(cmd.c_str(), "r");

							if (!pipe) {
								strcpy(response.payload, "[ERR] 管道启动失败。");
							} else {
								response.payload[0] = '\0';
								char lineBuffer[256];
								size_t maxLen = sizeof(response.payload) - 1;
								size_t currentLen = 0;

								while (fgets(lineBuffer, sizeof(lineBuffer), pipe) != NULL) {
									size_t lineLen = strlen(lineBuffer);
									if (currentLen + lineLen < maxLen) {
										strcat(response.payload, lineBuffer);
										currentLen += lineLen;
									} else {
										strcat(response.payload, "\n[...截断...]");
										break;
									}
								}
								_pclose(pipe);
								if (strlen(response.payload) == 0) {
									strcpy(response.payload, "执行完成 (无输出)。");
								}
							}
						}
						break;

//					case MSG_FILE_TRANS:
//						if (!isHighAuth) {
//							strcpy(response.payload, "权限不足。");
//						} else {
//							cout << "[文件] " << packet.payload << endl;
//							strcpy(response.payload, "文件接收成功。");
//						}
//						break;

					// ==============================================
					// 1. 处理文件头信息：文件名|文件大小
					// ==============================================
					case MSG_FILE_INFO:
						if (!isHighAuth) {
							strcpy(response.payload, "权限不足：拒绝接收文件。");
						} else {
							// 格式解析：文件名|大小 (例如: "test.jpg|10240")
							char fileName[256] = {0};
							long long fSize = 0;

							// 使用 sscanf 解析
							if (sscanf(packet.payload, "%[^|]|%lld", fileName, &fSize) == 2) {
								cout << "[文件传输] 准备接收: " << fileName << " 大小: " << fSize << " 字节" << endl;

								// 拼接保存路径 (默认存在服务端运行目录下)
								string savePath = "ServerRecv_" + string(fileName);

//cd /d D:\ & dir (Windows下跨盘符切换最好加 /d，用 & 连接两条命令)
								// 以二进制写模式打开
								if (fpUpload)
									fclose(fpUpload); // 防止上一次没关
								fpUpload = fopen(savePath.c_str(), "wb");

								if (fpUpload) {
									fileSizeExpected = fSize;
									fileSizeReceived = 0;
									strcpy(response.payload, "READY"); // 告诉客户端：准备好了，发数据吧
								} else {
									strcpy(response.payload, "ERROR: 服务端无法创建文件。");
								}
							} else {
								strcpy(response.payload, "ERROR: 文件头格式错误。");
							}
						}
						break;

					// ==============================================
					// 2. 处理文件数据块
					// ==============================================
					case MSG_FILE_CHUNK:
						if (!isHighAuth || !fpUpload) {
							// 如果没权限，或者没先发 MSG_FILE_INFO 就直接发数据，报错
							strcpy(response.payload, "ERROR: 传输顺序错误或权限不足。");
						} else {
							// 写入文件 (注意：必须使用 packet.dataLength)
							size_t written = fwrite(packet.payload, 1, packet.dataLength, fpUpload);
							fileSizeReceived += written;

							// 检查是否传输完成
							if (fileSizeReceived >= fileSizeExpected) {
								cout << "[文件传输] 接收完成！总大小: " << fileSizeReceived << endl;
								fclose(fpUpload);
								fpUpload = nullptr;
								strcpy(response.payload, "FINISH"); // 告诉客户端：全收到了
							} else {
								// 还没传完，回复当前进度 (可选，为了速度也可以不回包，但在本协议中一问一答比较稳)
								// 为了性能，我们可以只回一个简短的 ACK
								strcpy(response.payload, "ACK");
							}
						}
						break;


				}
				// 设置响应长度 (字符串类型直接用 strlen)
				response.dataLength = strlen(response.payload);
				send(clientSocket, (char *)&response, sizeof(DataPacket), 0);
			}
			// 循环结束后清理
			if (fpUpload) {
				fclose(fpUpload);
				fpUpload = nullptr;
			}
		}

		~Server() {
			closesocket(serverSocket);
			closesocket(clientSocket);
			WSACleanup();
		}
};

int main() {
	Server server;
	server.Start(9999);
	return 0;
}
