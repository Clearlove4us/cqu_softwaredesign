#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

// 链接 Winsock 库
//#pragma comment(lib, "ws2_32.lib")

using namespace std;

// 扫描单个端口的函数
// 返回值: true 表示端口开放, false 表示关闭或超时
bool ScanPort(const char *ip, int port) {
	// 1. 创建套接字
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		return false;
	}

	// 2. 设置目标地址结构
	sockaddr_in target;
	target.sin_family = AF_INET;
	target.sin_port = htons(port);
	target.sin_addr.s_addr = inet_addr(ip);

	// 3. 尝试连接
	// 注意：默认是阻塞模式，连接不存在的端口可能会等待几十秒超时
	// 为了作业演示，通常扫描本地(127.0.0.1)速度会很快
	// 如果需要扫描远程主机，建议使用 select 模型实现非阻塞 (代码会复杂很多)
	int result = connect(sock, (sockaddr *)&target, sizeof(target));

	bool isOpen = false;
	if (result == 0) {
		isOpen = true; // 连接成功，说明端口开放
	}

	// 4. 关闭套接字
	closesocket(sock);
	return isOpen;
}

int main() {
	// 初始化 Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "WSAStartup failed." << endl;
		return 1;
	}

	string targetIP;
	int startPort, endPort;

	cout << "========================================" << endl;
	cout << "          简易 TCP 端口扫描器           " << endl;
	cout << "========================================" << endl;

	// 获取用户输入
	cout << "请输入目标 IP (例如 127.0.0.1): ";
	cin >> targetIP;

	cout << "请输入起始端口 (例如 9990): ";
	cin >> startPort;

	cout << "请输入结束端口 (例如 10000): ";
	cin >> endPort;

	cout << "\n[开始扫描] 目标: " << targetIP << " [" << startPort << "-" << endPort << "]\n";
	cout << "----------------------------------------" << endl;

	int openPortsCount = 0;

	// 循环扫描
	for (int port = startPort; port <= endPort; port++) {
		// 为了显示正在运行，可以在同一行刷新显示进度
		// cout << "\r正在检查端口: " << port << "   " << flush;

		if (ScanPort(targetIP.c_str(), port)) {
			cout << "\n[+] 发现开放端口: " << port << " (OPEN) !!!" << endl;
			openPortsCount++;
		}
	}

	cout << "\n----------------------------------------" << endl;
	cout << "[扫描结束] 共发现 " << openPortsCount << " 个开放端口。" << endl;

	if (openPortsCount == 0) {
		cout << "提示: 未发现开放端口，请检查服务端是否开启，或防火墙是否拦截。" << endl;
	}

	// 清理 Winsock
	WSACleanup();

	system("pause");
	return 0;
}
