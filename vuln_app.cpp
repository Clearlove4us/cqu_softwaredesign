#include <stdio.h>
#include <string.h>
#include <windows.h>

// 目标：攻击者希望在不被授权的情况下调用这个函数
void secret_access() {
	printf("\n[!!!] 警告：已成功进入受保护的秘密函数！\n");
	system("calc.exe"); // 弹出计算器作为攻击成功的证明
	exit(0);
}

//void process_data(char *input) {
//	char buffer[64];
//	printf("处理数据的地址: %p\n", &buffer);
//
//	// 漏洞点：没有检查 input 的长度，直接拷贝到 64 字节的 buffer 中
//	strcpy(buffer, input);
//
//	printf("数据处理完成: %s\n", buffer);
//}


void process_data(char *input) {
	char buffer[64];

	// 故意用 memset 把 buffer 初始化为 'B' (0x42)，方便我们在内存里认出它
	memset(buffer, 'B', 64);

	printf("Buffer起始地址: %p\n", buffer);

	// 执行漏洞复制
	strcpy(buffer, input);

	printf("数据处理完成。现在开始打印栈内存布局...\n");
	printf("----------------------------------------\n");

	// 【内存侦探核心代码】
	// 我们把 buffer 当作一个起点，向后扫描 32 个“格子”（每个格子4字节，共128字节）
	unsigned int *spy = (unsigned int *)buffer;

	for (int i = 0; i < 32; i++) {
		// 读取当前格子的值
		unsigned int val = spy[i];

		// 打印：偏移量 | 内存地址 | 内存里的值
		printf("偏移 %d: [地址 %p] = 0x%08X", i * 4, &spy[i], val);

		// 自动识别：如果这个值看起来像代码地址 (比如 0x00401xxx)，它很可能就是返回地址！
		// 一般 main 函数里的地址都在 0x00401000 到 0x00402000 之间
		if (val > 0x00401000 && val < 0x00402000) {
			printf(" <--- 【找到啦！】这看起来像返回地址(EIP)");
		}
		printf("\n");
	}
	printf("----------------------------------------\n");
}

int main(int argc, char *argv[]) {
	printf("secret_access函数的地址：%p\n", secret_access);
	if (argc < 2) {
		printf("用法: %s <输入字符串>\n", argv[0]);
		return 1;
	}
	process_data(argv[1]);
	return 0;
}
//cd Documents\c++\softwaredesign2026112 & gcc vuln_app.cpp -o vuln_app.exe -m32 -fno-stack-protector -g
//只运行，这是32位编译，不要改变
