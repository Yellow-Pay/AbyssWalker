#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
enum {encrypt,decrypt};
void des_run(char out[8],char in[8],bool type);
void des_setkey(const char key[8]);
static void f_func(bool in[32],const bool ki[48]);
static void s_func(bool out[32],const bool in[48]);
static void transform(bool *out, bool *in, const char *table, int len);
static void xor(bool *ina, const bool *inb, int len);
static void rotatel(bool *in, int len, int loop);
static void bytetobit(bool *out,const char *in, int bits);
static void bittobyte(char *out, const bool *in, int bits);
const static char ip_table[64]={58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
const static char ipr_table[64]={40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
static const char e_table[48]={32,1, 2, 3, 4, 5,4, 5, 6, 7, 8, 9,8, 9, 10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
const static char p_table[32]={16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
const static char pc1_table[56]={
	57,49,41,33,25,17,9,1,
	58,50,42,34,26,18,10,2,
	59,51,43,35,27,19,11,3,
	60,52,44,36,63,55,47,39,
	31,23,15,7,62,54,46,38,
	30,22,14,6,61,53,45,37,
	29,21,13,5,28,20,12,4
};
const static char pc2_table[48]={
	14,17,11,24,1,5,3,28,
	15,6,21,10,23,19,12,4,
	26,8,16,7,27,20,13,2,
	41,52,31,37,47,55,30,40,
	51,45,33,48,44,49,39,56,
	34,53,46,42,50,36,29,32
};
const static char loop_table[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
const static char s_box[8][4][16]={
	//s1
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
	//s2
	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
	//s3
	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
	//s4
	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
	//s5
	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
	//s6
	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
	//s7
	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
	//s8
	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};
static bool subkey[16][48];
void des_run(char out[8],char in[8], bool type)
{
	static bool m[64],tmp[32],*li=&m[0], *ri=&m[32];
	bytetobit(m,in,64);
	transform(m,m,ip_table,64);
	if(type==encrypt){
		for(int i=0;i<16;i++){
			memcpy(tmp,ri,32);
			f_func(ri,subkey[i]);
			xor(ri,li,32);
			memcpy(li,tmp,32);
		}
	}else{
		for(int i=15;i>=0;i--){
			memcpy(tmp,li,32);
			f_func(li,subkey[i]);
			xor(li,ri,32);
			memcpy(ri,tmp,32);
		}
	}
	transform(m,m,ipr_table,64);
	bittobyte(out,m,64);
}
void des_setkey(const char key[8])
{
	static bool k[64], *kl=&k[0], *kr=&k[28];
	bytetobit(k,key,64);
	transform(k,k,pc1_table,56);
	for(int i=0;i<16;i++)
	{
		rotatel(kl,28,loop_table[i]);
		rotatel(kr,28,loop_table[i]);
		transform(subkey[i],k,pc2_table,48);
	}
}
void f_func(bool in[32],const bool ki[48])
{
	static bool mr[48];
	transform(mr,in,e_table,48);
	xor(mr,ki,48);
	s_func(in,mr);
	transform(in,in,p_table,32);
}
void s_func(bool out[32],const bool in[48])
{
	for(char i=0,j,k;i<8;i++,in+=6,out+=4)
	{
		j=(in[0]<<1)+in[5];
		k=(in[1]<<3)+(in[2]<<2)+(in[3]<<1)+in[4];
		bytetobit(out,&s_box[i][j][k],4);
	}
}
void transform(bool *out,bool *in,const char *table,int len)
{
	static bool tmp[256];
	for(int i=0;i<len;i++)
	      tmp[i]=in[table[i]-1];
	memcpy(out,tmp,len);
}
void xor(bool *ina,const bool *inb,int len)
{
	for(int i=0;i<len;i++)
	      ina[i]^=inb[i];
}
void rotatel(bool *in,int len,int loop)
{
	static bool tmp[256];
	memcpy(tmp,in,loop);
	memcpy(in,in+loop,len-loop);
	memcpy(in+len-loop,tmp,loop);
}
void bytetobit(bool *out,const char *in,int bits)
{
	for(int i=0;i<bits;i++)
	      out[i]=(in[i/8]>>(i%8)) &1;
}
void bittobyte(char *out,const bool *in,int bits)
{
	memset(out,0,(bits+7)/8);
	for(int i=0;i<bits;i++)
	      out[i/8]|=in[i]<<(i%8);
}

const unsigned char GLOBAL_KEY_MAP[0x100] = 
{
0x00,0x80,0x02,0x82,0x04,0x84,0x06,0x86,0x08,0x88,0x0a,0x8a,0x0c,0x8c,0x0e,0x8e,
0x10,0x90,0x12,0x92,0x14,0x94,0x16,0x96,0x18,0x98,0x1a,0x9a,0x1c,0x9c,0x1e,0x9e,
0x20,0xa0,0x22,0xa2,0x24,0xa4,0x26,0xa6,0x28,0xa8,0x2a,0xaa,0x2c,0xac,0x2e,0xae,
0x30,0xb0,0x32,0xb2,0x34,0xb4,0x36,0xb6,0x38,0xb8,0x3a,0xba,0x3c,0xbc,0x3e,0xbe,
0x40,0xc0,0x42,0xc2,0x44,0xc4,0x46,0xc6,0x48,0xc8,0x4a,0xca,0x4c,0xcc,0x4e,0xce,
0x50,0xd0,0x52,0xd2,0x54,0xd4,0x56,0xd6,0x58,0xd8,0x5a,0xda,0x5c,0xdc,0x5e,0xde,
0x60,0xe0,0x62,0xe2,0x64,0xe4,0x66,0xe6,0x68,0xe8,0x6a,0xea,0x6c,0xec,0x6e,0xee,
0x70,0xf0,0x72,0xf2,0x74,0xf4,0x76,0xf6,0x78,0xf8,0x7a,0xfa,0x7c,0xfc,0x7e,0xfe,
0x01,0x81,0x03,0x83,0x05,0x85,0x07,0x87,0x09,0x89,0x0b,0x8b,0x0d,0x8d,0x0f,0x8f,
0x11,0x91,0x13,0x93,0x15,0x95,0x17,0x97,0x19,0x99,0x1b,0x9b,0x1d,0x9d,0x1f,0x9f,
0x21,0xa1,0x23,0xa3,0x25,0xa5,0x27,0xa7,0x29,0xa9,0x2b,0xab,0x2d,0xad,0x2f,0xaf,
0x31,0xb1,0x33,0xb3,0x35,0xb5,0x37,0xb7,0x39,0xb9,0x3b,0xbb,0x3d,0xbd,0x3f,0xbf,
0x41,0xc1,0x43,0xc3,0x45,0xc5,0x47,0xc7,0x49,0xc9,0x4b,0xcb,0x4d,0xcd,0x4f,0xcf,
0x51,0xd1,0x53,0xd3,0x55,0xd5,0x57,0xd7,0x59,0xd9,0x5b,0xdb,0x5d,0xdd,0x5f,0xdf,
0x61,0xe1,0x63,0xe3,0x65,0xe5,0x67,0xe7,0x69,0xe9,0x6b,0xeb,0x6d,0xed,0x6f,0xef,
0x71,0xf1,0x73,0xf3,0x75,0xf5,0x77,0xf7,0x79,0xf9,0x7b,0xfb,0x7d,0xfd,0x7f,0xff,
};

const int KEY_LENGTH = 8;

const unsigned char InitKey1[KEY_LENGTH] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
const unsigned char InitKey2[KEY_LENGTH] = {0xb0,0x32,0xb2,0x34,0xb4,0x36,0xb6,0x38};

const unsigned char Network1[KEY_LENGTH] = {0x1d,0xb5,0x7f,0x4e,0xc7,0xae,0x11,0xc7};
const unsigned char Network2[KEY_LENGTH] = {0x64,0xf2,0xa7,0xc0,0x4b,0xc8,0x56,0xb7};

const unsigned char Conn1Key1[KEY_LENGTH] = {0xeb,0xc6,0x3c,0x4b,0x42,0xc4,0xf6,0x2b};
const unsigned char Conn1Key2[KEY_LENGTH] = {0xeb,0x47,0x3c,0xca,0x42,0x45,0x77,0xaa};

const unsigned char Conn2Key1[KEY_LENGTH] = {0xb2,0x69,0xba,0x51,0xe4,0xa0,0x2b,0x09};
const unsigned char Conn2Key2[KEY_LENGTH] = {0x33,0xe8,0x3b,0xd0,0x65,0x21,0xaa,0x88};

void HexDump(const char *title, const unsigned char *content, size_t size)
{
	printf("%s  ", title);
	for (size_t i = 0; i < size; i++)
	{
		printf("0x%02x ", content[i]);
	}
	printf("\n");
}

void RedDisplayColor () {
	printf("\033[1;31m");
}

void ResetDisplayColor () {
	printf("\033[0m");
}

#define KEY_OUTPUT_BEGIN RedDisplayColor();
#define KEY_OUTPUT_END ResetDisplayColor();

void ValidateKeyPair(const unsigned char *key1, const unsigned char *key2)
{
	unsigned char new_key1[KEY_LENGTH];
	unsigned char new_key2[KEY_LENGTH];
	memset(new_key1, 0, KEY_LENGTH);
	memset(new_key2, 0, KEY_LENGTH);
	bool pass = true;
	for (int i = 0; i < KEY_LENGTH; i++)
	{
		new_key1[i] = GLOBAL_KEY_MAP[key2[i]];
		new_key2[i] = GLOBAL_KEY_MAP[key1[i]];
		pass &= (new_key1[i] == key1[i] && new_key2[i] == key2[i]);
	}
	HexDump("old_key1:", key1, KEY_LENGTH);
	HexDump("old_key2:", key2, KEY_LENGTH);
	HexDump("new_key1:", new_key1, KEY_LENGTH);
	HexDump("new_key2:", new_key2, KEY_LENGTH);
	KEY_OUTPUT_BEGIN
	printf("ValidateKeyPair result=%s\n", pass ? "PASS" : "FAILED");
	KEY_OUTPUT_END
}

void ValidateAllKeyPairs()
{
	KEY_OUTPUT_BEGIN
	printf("========== ValidateAllKeyPairs ==========\n");
	KEY_OUTPUT_END
	printf("========== InitKey1 & InitKey2 ==========\n");
	ValidateKeyPair(InitKey1, InitKey2);
	printf("========= Conn1Key1 & Conn1Key2 =========\n");
	ValidateKeyPair(Conn1Key1, Conn1Key2);
	printf("========= Conn2Key1 & Conn2Key2 =========\n");
	ValidateKeyPair(Conn2Key1, Conn2Key2);
	KEY_OUTPUT_BEGIN
	printf("======== ValidateKeyPair Finish =========\n");
	KEY_OUTPUT_END
}

int main()
{
	ValidateAllKeyPairs();
	return 0;
}
