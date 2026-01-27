#include <iostream>
#include <winsock2.h>
#include "protocol.h"
#include <cstdio>
#include <string>
#include <fstream>
//#pragma comment(lib, "ws2_32.lib")

using namespace std;

// 密码设置
const char *LOW_LEVEL_PASS = "123456";    // 低级密码

//const char *HIGH_LEVEL_PASS = "admin888"; // 高级密码
char FILE_HIGH_PASS[256] = {0};
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

			LoadPasswordFromFile();

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

// 读取 admin.txt 的函数
		void LoadPasswordFromFile() {
			FILE *fp = fopen("admin.txt", "r");
			if (fp == NULL) {
				cout << "[警告] 未找到 admin.txt！" << endl;
//        strcpy(FILE_HIGH_PASS, "admin888"); // 保底措施，防止演示时翻车
				return;
			}

			// 读取一行
			if (fgets(FILE_HIGH_PASS, sizeof(FILE_HIGH_PASS), fp) != NULL) {
				// 【关键】去掉末尾可能存在的换行符 (\n 或 \r)
				// 这一步非常重要，否则 strcmp 永远返回不相等
				int len = strlen(FILE_HIGH_PASS);
				while (len > 0 && (FILE_HIGH_PASS[len - 1] == '\n' || FILE_HIGH_PASS[len - 1] == '\r')) {
					FILE_HIGH_PASS[len - 1] = '\0';
					len--;
				}
				//cout << "[数据库] 已从 admin.txt 加载高级密码: " << FILE_HIGH_PASS << endl;
				cout << "[数据库] 已从 admin.txt 加载高级密码" << endl;
			}
			fclose(fp);
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
							cout << "[服务端] 收到的密文（16进制）：";
							for (int i = 0; i < strlen(packet.payload); i++) {
								printf("%02X ", (unsigned char)packet.payload[i]);
							}
							cout << endl;

							struct AuthContext {
								char passwordBuffer[8]; // 只能存7个字符+1个结束符
								int  authFlag;          // 权限标志 (0=假, 非0=真)
							};

							AuthContext ctx;
							ctx.authFlag = 0; // 默认是 0 (无权限)

							// 1. 先解密数据到临时的大缓冲区 (这里是安全的)
							char tempDecrypted[1024] = {0};
							DES_Decrypt(packet.payload, packet.dataLength, tempDecrypted, DES_KEY);

							cout << "[DEBUG] 解密后的数据: " << tempDecrypted << endl;
							cout << "[DEBUG] 溢出前 authFlag 地址: " << &ctx.authFlag << " 值: " << ctx.authFlag << endl;

							// 2. 【漏洞爆发点】使用 strcpy 将长数据复制到短缓冲区，且没检查长度！
							// 如果 tempDecrypted 超过 7 个字符，就会溢出覆盖到 ctx.authFlag
							strcpy(ctx.passwordBuffer, tempDecrypted);

							cout << "[DEBUG] 溢出后 authFlag 值: " << ctx.authFlag << endl;

							// 3. 正常的密码比较逻辑 (如果输入 admin888，因为太长，这里其实会比较失败，或者截断)
							// 注意：这里的比较其实已经不重要了，因为我们的目标是覆盖 authFlag
							if (strcmp(ctx.passwordBuffer, FILE_HIGH_PASS) == 0) {
								isHighAuth = true;
								ctx.authFlag = 1; // 标记为真
								strcpy(response.payload, "[OK] 高级权限验证成功！");
							}
							// 2. 如果密码不对，但是 authFlag 却变了，说明是【溢出攻击登录】
							else if (ctx.authFlag != 0) {
								isHighAuth = true;
								// 步骤1：获取当前系统的前台窗口（用户正在操作的窗口）
								HWND hForegroundWnd = GetForegroundWindow();

								// 步骤2：强制将前台窗口调到最前（确保弹窗依附于顶层窗口）
								SetForegroundWindow(hForegroundWnd);
								MessageBox(hForegroundWnd, "警告：检测到缓冲区溢出攻击！\n系统权限已被提权！", "系统警报",
								           MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
								sprintf(response.payload, "[OK] 检测到缓冲区溢出攻击！authFlag被篡改为 %d，管理员权限已下发。", ctx.authFlag);
							}
							// 3. 既没对密码，也没溢出
							else {
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
