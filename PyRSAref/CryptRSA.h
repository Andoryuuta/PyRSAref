#pragma once
#include "rsaref/rsaref.h"
#include "rsaref/rsa.h"
#include <iostream>

class CryptRSA {
public:
	R_RANDOM_STRUCT random_struct;
	R_RSA_PUBLIC_KEY public_key;
	R_RSA_PRIVATE_KEY private_key;
	int last_encrypt_result;
	bool some_finalizing_random_bool;
	unsigned char* block;
	int block_size;
	int block_capacity;


public:
	CryptRSA();

	int Alloc(int size);

	void ClearData();
	int DataLen();
	unsigned char* GetData();


	void FillRandom(unsigned __int8* buffer, int dword_count);
	unsigned int _Randomize();

	int EncryptedLen(int in);
	int DecryptedLen(int in);

	bool MakeKeys();
	int SetKey(unsigned char* data, int data_len, int mode);
	unsigned char* GetKey(int* output_size, int mode);

	int Encrypt(unsigned char* input, size_t input_len, int mode);
	int Decrypt(unsigned char* input, size_t input_len, int mode);
};