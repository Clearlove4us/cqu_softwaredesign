#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>

// ==========================================
// 1. 协议定义部分
// ==========================================

// 定义消息类型
enum MessageType {
	MSG_LOGIN_LOW = 1,    // 低级权限登录请求
	MSG_LOGIN_HIGH,       // 高级权限登录请求
	MSG_COMMAND,          // 执行CMD命令
	//MSG_FILE_TRANS,       // 文件传输请求

	MSG_FILE_INFO,        // 发送文件名和大小
	MSG_FILE_CHUNK,       // 发送文件二进制数据块

	MSG_RESPONSE          // 服务端回传的消息
};

// 定义数据包结构
struct DataPacket {
	int type;             // 消息类型
	int dataLength;       // 【关键】数据长度 (解密时必须用这个，不能用strlen)
	char payload[8192];   // 数据载荷 (8KB 缓冲区)
};

// ==========================================
// 2. DES 算法实现部分 (MiniDES)
// ==========================================

// 所有的常量和函数都加上 static 关键字，防止多重定义报错
static const int IP_Table[64] = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
static const int IP_1_Table[64] = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
static const int E_Table[48] = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
static const int P_Table[32] = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
static const int S_Box[8][4][16] = { {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}}, {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}}, {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}}, {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}}, {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}}, {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}}, {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}}, {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}} };
static const int PC_1[56] = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
static const int PC_2[48] = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
static const int LS[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

namespace MiniDES {
	typedef bool(*BitArray)[64];
	// 静态辅助函数
	static void GenSubKeys(const char *key, bool subKeys[16][48]) {
		bool K[64], C[28], D[28];
		for (int i = 0; i < 64; ++i)
			K[i] = (key[i / 8] >> (7 - (i % 8))) & 1;
		for (int i = 0; i < 28; ++i) {
			C[i] = K[PC_1[i] - 1];
			D[i] = K[PC_1[i + 28] - 1];
		}
		for (int r = 0; r < 16; ++r) {
			bool tC[28], tD[28];
			for (int i = 0; i < 28; ++i) {
				tC[i] = C[(i + LS[r]) % 28];
				tD[i] = D[(i + LS[r]) % 28];
			}
			memcpy(C, tC, sizeof(C));
			memcpy(D, tD, sizeof(D));
			for (int i = 0; i < 48; ++i) {
				int idx = PC_2[i] - 1;
				subKeys[r][i] = (idx < 28) ? C[idx] : D[idx - 28];
			}
		}
	}
	static void ProcessBlock(const char *blk, char *out, bool subKeys[16][48], bool isEnc) {
		bool M[64], L[32], R[32], nL[32], tmp[48], M_IP[64];
		for (int i = 0; i < 64; ++i)
			M[i] = (blk[i / 8] >> (7 - (i % 8))) & 1;
		for (int i = 0; i < 64; ++i)
			M_IP[i] = M[IP_Table[i] - 1];
		for (int i = 0; i < 32; ++i) {
			L[i] = M_IP[i];
			R[i] = M_IP[i + 32];
		}
		for (int r = 0; r < 16; ++r) {
			memcpy(nL, R, sizeof(R));
			int kIdx = isEnc ? r : (15 - r);
			bool E_R[48];
			for (int i = 0; i < 48; ++i)
				E_R[i] = R[E_Table[i] - 1];
			for (int i = 0; i < 48; ++i)
				tmp[i] = E_R[i] ^ subKeys[kIdx][i];
			bool S_Out[32];
			for (int i = 0; i < 8; ++i) {
				int row = (tmp[i * 6] * 2) + tmp[i * 6 + 5];
				int col = tmp[i * 6 + 1] * 8 + tmp[i * 6 + 2] * 4 + tmp[i * 6 + 3] * 2 + tmp[i * 6 + 4];
				int val = S_Box[i][row][col];
				for (int j = 0; j < 4; ++j)
					S_Out[i * 4 + j] = (val >> (3 - j)) & 1;
			}
			bool P_Out[32];
			for (int i = 0; i < 32; ++i)
				P_Out[i] = S_Out[P_Table[i] - 1];
			for (int i = 0; i < 32; ++i)
				R[i] = L[i] ^ P_Out[i];
			memcpy(L, nL, sizeof(L));
		}
		bool Fin[64], Out[64];
		for (int i = 0; i < 32; ++i) {
			Fin[i] = R[i];
			Fin[i + 32] = L[i];
		}
		for (int i = 0; i < 64; ++i)
			Out[i] = Fin[IP_1_Table[i] - 1];
		memset(out, 0, 8);
		for (int i = 0; i < 64; ++i)
			if (Out[i])
				out[i / 8] |= (1 << (7 - (i % 8)));
	}
}

// ==========================================
// 3. 对外接口 (Static 函数，可安全包含)
// ==========================================

// 【新增参数】inputLen: 必须传入数据的真实长度
static void DES_Encrypt(const char *input, int inputLen, char *output, const char *key) {
	bool subKeys[16][48];
	char finalKey[8] = { 0 };
	strncpy(finalKey, key, 8);
	MiniDES::GenSubKeys(finalKey, subKeys);

	// 计算需要多少个8字节块
	int blockCount = (inputLen + 7) / 8;

	for (int i = 0; i < blockCount; ++i) {
		char inBlock[8] = { 0 }; // 自动补零填充 (Zero Padding)

		int copyLen = (inputLen - i * 8) > 8 ? 8 : (inputLen - i * 8);
		if (copyLen > 0)
			memcpy(inBlock, input + i * 8, copyLen);

		MiniDES::ProcessBlock(inBlock, output + i * 8, subKeys, true);
	}
}

// 【新增参数】inputLen: 这里传入的是密文的总长度 (通常是 DataPacket.dataLength)
static void DES_Decrypt(const char *input, int inputLen, char *output, const char *key) {
	bool subKeys[16][48];
	char finalKey[8] = { 0 };
	strncpy(finalKey, key, 8);
	MiniDES::GenSubKeys(finalKey, subKeys);

	int blockCount = inputLen / 8;
	for (int i = 0; i < blockCount; ++i) {
		char outBlock[8];
		MiniDES::ProcessBlock(input + i * 8, outBlock, subKeys, false);
		memcpy(output + i * 8, outBlock, 8);
	}
	// 加上结束符，方便 printf (但请注意，如果是二进制文件数据，\0 也没用)
	// 我们尽量在解密后保证末尾有个 \0 防止字符串操作越界
	output[inputLen] = '\0';
}

#endif
