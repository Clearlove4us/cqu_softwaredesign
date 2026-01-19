#include <iostream>
#include <winsock2.h>
#include <string>
#include <limits>
#include "Protocol.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// 【修改】必须和服务端一致
const char *DES_KEY = "12345678";

class Client {
	private:
		SOCKET clientSocket;
		bool isConnected = false;
		bool isHighLevel = false;

		void ClearInputBuffer() {
			cin.clear();
			cin.ignore(numeric_limits<streamsize>::max(), '\n');
		}

	public:
		Client() {
			clientSocket = INVALID_SOCKET;
		}

		bool Connect(const char *ip, int port) {
			if (isConnected)
				CloseConnection();
			WSADATA wsaData;
			WSAStartup(MAKEWORD(2, 2), &wsaData);
			clientSocket = socket(AF_INET, SOCK_STREAM, 0);

			sockaddr_in serverAddr;
			serverAddr.sin_family = AF_INET;
			serverAddr.sin_port = htons(port);
			serverAddr.sin_addr.s_addr = inet_addr(ip);

			if (connect(clientSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
				return false;
			}
			isConnected = true;
			isHighLevel = false;
			return true;
		}

		void CloseConnection() {
			if (clientSocket != INVALID_SOCKET) {
				closesocket(clientSocket);
				clientSocket = INVALID_SOCKET;
			}
			WSACleanup();
			isConnected = false;
			isHighLevel = false;
		}

		// DES 加密
		string SendAndRecv(int type, const char *data) {
			if (!isConnected)
				return "错误：未连接服务端";

			DataPacket packet;
			packet.type = type;
			memset(packet.payload, 0, sizeof(packet.payload));

			if (type == MSG_LOGIN_HIGH) {
				// 1. 计算明文长度
				int plainLen = strlen(data);

				// 2. 调用真实 DES 加密
				DES_Encrypt(data, plainLen, packet.payload, DES_KEY);

				// 3. 【重点】计算密文长度 (必须是8的倍数)
				// 例如 "123" (3字节) -> 加密后变成 8字节
				packet.dataLength = ((plainLen + 7) / 8) * 8;
			} else {
				// 普通消息直接拷贝
				strcpy(packet.payload, data);
				packet.dataLength = strlen(packet.payload);
			}

			if (send(clientSocket, (char *)&packet, sizeof(DataPacket), 0) == SOCKET_ERROR) {
				return "发送失败";
			}

			DataPacket response;
			if (recv(clientSocket, (char *)&response, sizeof(DataPacket), 0) > 0) {
				// 确保末尾有 \0，防止打印乱码
				response.payload[response.dataLength] = '\0';
				return string(response.payload);
			}
			return "服务端无响应";
		}

		bool DoLoginSequence() {
			char buffer[1024];
			cout << "\n=== 远程控制系统 - 登录 ===" << endl;

			// 步骤1：低级登录
			while (true) {
				cout << "\n[步骤1] 低级密码 (exit退出): ";
				cin >> buffer;
				if (strcmp(buffer, "exit") == 0)
					return false;

				string resp = SendAndRecv(MSG_LOGIN_LOW, buffer);
				cout << "服务端回复: " << resp << endl;

				if (resp.find("[OK]") != string::npos)
					break;
			}

			// 步骤2：高级登录
			while (true) {
				cout << "\n[步骤2] 验证高级权限? (y/n): ";
				char choice;
				cin >> choice;
				ClearInputBuffer();

				if (choice == 'n' || choice == 'N')
					break;
				if (choice == 'y' || choice == 'Y') {
					cout << "高级密码: ";
					cin >> buffer;
					string resp = SendAndRecv(MSG_LOGIN_HIGH, buffer);
					cout << "服务端回复: " << resp << endl;

					if (resp.find("[OK]") != string::npos) {
						isHighLevel = true;
						break;
					}
				} else {
					cout << "无效输入" << endl;
				}
			}
			return true;
		}

		void ShowWorkMenu() {
			int choice;
			char buffer[1024]; // 临时缓存

			while (true) {
				cout << "\n======= 工作台 [" << (isHighLevel ? "高级" : "普通") << "] =======" << endl;
				cout << "1. 远程命令" << endl;
				cout << "2. " << (isHighLevel ? "文件传输" : "(禁用) 文件传输") << endl;
				cout << "9. 注销" << endl;
				cout << "0. 退出" << endl;
				cout << "请选择: ";

				if (!(cin >> choice)) {
					cout << "输入无效" << endl;
					ClearInputBuffer();
					continue;
				}
				ClearInputBuffer(); // 清除回车

				if (choice == 0)
					exit(0);
				if (choice == 9)
					return;

				if (choice == 1) {
					cout << "输入命令: ";
					// 使用 getline 支持带空格的命令 (如 dir /w)
					cin.getline(buffer, sizeof(buffer));
					string resp = SendAndRecv(MSG_COMMAND, buffer);
					cout << "结果:\n" << resp << endl;
				} else if (choice == 2) {
					if (!isHighLevel) {
						cout << "权限不足！" << endl;
					} else {
						UploadFile();
					}
				}
			}
		}

		void UploadFile() {
			char filePath[256];
			cout << "请输入要上传的文件绝对路径 (例如 D:\\test.jpg): ";
			// 清理一下缓冲区防止跳过
			// cin.ignore(); // 视情况加
			cin.getline(filePath, sizeof(filePath));

			// 1. 打开本地文件 (二进制读)
			FILE *fp = fopen(filePath, "rb");
			if (!fp) {
				cout << ">> 错误：无法打开文件，请检查路径。" << endl;
				return;
			}

			// 2. 获取文件名和大小
			fseek(fp, 0, SEEK_END);
			long long fileSize = ftell(fp);
			rewind(fp); // 回到文件头

			// 提取纯文件名 (去除路径 D:\Photos\a.jpg -> a.jpg)
			string pathStr = filePath;
			size_t lastSlash = pathStr.find_last_of("\\/");
			string fileName = (lastSlash == string::npos) ? pathStr : pathStr.substr(lastSlash + 1);

			cout << ">> 正在准备上传: " << fileName << " (" << fileSize << " bytes)..." << endl;

			// 3. 发送【文件头信息】 (格式: filename|filesize)
			char infoBuffer[1024];
			sprintf(infoBuffer, "%s|%lld", fileName.c_str(), fileSize);

			string resp = SendAndRecv(MSG_FILE_INFO, infoBuffer);
			if (resp.find("READY") == string::npos) {
				cout << ">> 服务端拒绝接收: " << resp << endl;
				fclose(fp);
				return;
			}

			// 4. 循环发送【数据块】
			char chunkBuffer[4096]; // 每次传 4KB
			long long totalSent = 0;

			while (!feof(fp) && totalSent < fileSize) {
				// 读取一块
				int bytesRead = fread(chunkBuffer, 1, sizeof(chunkBuffer), fp);
				if (bytesRead <= 0)
					break;

				// 构造数据包并发送 (这里不能用 SendAndRecv，因为它是针对字符串设计的)
				// 我们需要手动发送 binary 数据
				DataPacket packet;
				packet.type = MSG_FILE_CHUNK;
				packet.dataLength = bytesRead;
				memcpy(packet.payload, chunkBuffer, bytesRead);

				if (send(clientSocket, (char *)&packet, sizeof(DataPacket), 0) == SOCKET_ERROR) {
					cout << ">> 发送中断！" << endl;
					break;
				}

				// 等待服务端 ACK (防止粘包，也是一问一答机制)
				DataPacket srvResp;
				if (recv(clientSocket, (char *)&srvResp, sizeof(DataPacket), 0) > 0) {
					if (strstr(srvResp.payload, "FINISH")) {
						cout << "\n>> 上传成功！服务端已确认接收。" << endl;
						break;
					}
					// 如果是 ACK，继续发下一块
				} else {
					cout << ">> 服务端无响应。" << endl;
					break;
				}

				totalSent += bytesRead;
				// 打印简单的进度条
				if (totalSent % (1024 * 1024) == 0)
					cout << ".";
			}

			fclose(fp);
			cout << ">> 传输结束。" << endl;
		}
};

int main() {
	Client client;
	while (true) {
		if (!client.Connect("127.0.0.1", 9999)) {
			cout << "连接失败，3秒后重试..." << endl;
			Sleep(3000);
			continue;
		}
		if (!client.DoLoginSequence())
			break;
		client.ShowWorkMenu();
		client.CloseConnection();
		cout << "\n>> 已注销。\n" << endl;
	}
	return 0;
}
