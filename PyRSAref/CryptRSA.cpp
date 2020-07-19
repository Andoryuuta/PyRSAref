#include "CryptRSA.h"
#include <Windows.h>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <stdexcept>

CryptRSA::CryptRSA()
{
	srand(time(0) * GetCurrentProcessId());

	R_RandomInit(&this->random_struct);
	std::memset(&this->public_key, 0, sizeof(this->public_key));
	std::memset(&this->private_key, 0, sizeof(this->private_key));

	this->some_finalizing_random_bool = 0;
	this->block = nullptr;
	this->block_size = 0;
	this->block_capacity = 0;
	this->last_encrypt_result = 0;
}


unsigned char random_byte() {
    return rand() & 0xFF;
}

void CryptRSA::FillRandom(unsigned __int8* buffer, int size)
{
    for (int i = 0; i < size; i++) {
        buffer[i] = random_byte();
    }
}

int CryptRSA::EncryptedLen(int in)
{
    return (in / 48 + 1) << 6;
}

int CryptRSA::DecryptedLen(int in)
{
    return 48 * (in / 64);
}

bool CryptRSA::MakeKeys()
{
    this->_Randomize();

    R_RSA_PROTO_KEY proto = { 512, 1 };
    return R_GeneratePEMKeys(&this->public_key, &this->private_key, &proto, &this->random_struct) == 0;
}

void CryptRSA::ClearData()
{
    if (this->block)
    {
        free((void*)this->block);
        this->block = 0;
    }
    this->block_size = 0;
    this->block_capacity = 0;
}

int CryptRSA::Alloc(int size)
{
    this->ClearData();

    if (size <= 0)
        return 0;

    this->block = reinterpret_cast<unsigned char*>(malloc(size));
    if (!this->block)
        return 0;

    this->block_capacity = size;

    return 1;
}

unsigned int CryptRSA::_Randomize()
{
    int result; 
    unsigned int random_bytes_needed;
    unsigned char v3[256];

    if (this->some_finalizing_random_bool)
    {
        R_RandomFinal(&this->random_struct);
        R_RandomInit(&this->random_struct);
    }
    do
    {
        result = R_GetRandomBytesNeeded(&random_bytes_needed, &this->random_struct);
        if (!random_bytes_needed)
            break;
        this->FillRandom(v3, 256);
        R_RandomUpdate(&this->random_struct, v3, 256);
        result = random_bytes_needed;
    } while (random_bytes_needed);
    return result;
}

int CryptRSA::SetKey(unsigned char* data, int data_len, int mode)
{
    this->_Randomize();

    if (mode == 1)
    {
        if(data_len != sizeof(R_RSA_PRIVATE_KEY))
            throw std::runtime_error("data_len != sizeof(R_RSA_PRIVATE_KEY)");
        memcpy(&this->private_key, data, data_len);
    }
    else
    {
        if (data_len != sizeof(R_RSA_PUBLIC_KEY))
            throw std::runtime_error("data_len != sizeof(R_RSA_PUBLIC_KEY)");
        memcpy(&this->public_key, data, data_len);
    }
    //this->public_key.bits = 512;

    return 1;
}

unsigned char* CryptRSA::GetKey(int* output_size, int mode)
{
    if (mode == 1) {
        *output_size = sizeof(R_RSA_PRIVATE_KEY);
        return reinterpret_cast<unsigned char*>(&this->private_key);
    }
    else {
        *output_size = sizeof(R_RSA_PUBLIC_KEY);
        return reinterpret_cast<unsigned char*>(&this->public_key);
    }
    return nullptr;
}

int CryptRSA::Encrypt(unsigned char* input, size_t input_len, int mode)
{
    int input_idx;
    signed int remaining_input_bytes;
    int output_idx;
    unsigned int cur_round_input_bytes;
    int result;
    unsigned int output_len;

    input_idx = 0;
    output_idx = 0;
    remaining_input_bytes = 256;

    int encrypted_length = this->EncryptedLen(256);
    this->Alloc(encrypted_length);

    while (1)
    {
        output_len = 0;


        // Cap if remaining is > 48.
        cur_round_input_bytes = remaining_input_bytes;
        if (remaining_input_bytes > 48)
            cur_round_input_bytes = 48;
        
        // Private vs public encrypt based on mode.
        if (mode == 1) {
            result = RSAPrivateEncrypt(
                &this->block[output_idx],
                &output_len,
                &input[input_idx],
                cur_round_input_bytes,
                &this->private_key);
        }
        else {
            result = RSAPublicEncrypt(
                &this->block[output_idx],
                &output_len,
                &input[input_idx],
                cur_round_input_bytes,
                &this->public_key,
                &this->random_struct);
        }

        if (result)
            break;

        input_idx += cur_round_input_bytes;
        this->block_size += output_len;
        output_idx = this->block_size;
        remaining_input_bytes -= cur_round_input_bytes;
        if (!remaining_input_bytes)
            return 1;
    }
    this->last_encrypt_result = result;
    return 0;

}


int CryptRSA::Decrypt(unsigned char* input, size_t input_len, int mode)
{
    int decrypted_length = this->DecryptedLen(input_len);
    int alloc_result = this->Alloc(decrypted_length);

    if (alloc_result && input_len)
    {
        unsigned int output_write_idx = this->block_size;
        unsigned int input_read_idx = 0;
        size_t remaining_bytes = input_len;
        while (1)
        {
            unsigned int decrypted_count = 0;
            int decrypt_result = 0;

            // Private vs public decryption based on mode.
            if (mode == 1) {
                decrypt_result = RSAPrivateDecrypt(
                    &this->block[output_write_idx],
                    &decrypted_count,
                    &input[input_read_idx],
                    64,
                    &this->private_key);
            }
            else {
                decrypt_result = RSAPublicDecrypt(
                    &this->block[output_write_idx],
                    &decrypted_count,
                    &input[input_read_idx],
                    64,
                    &this->public_key);
            }

            if (decrypt_result) {
                this->last_encrypt_result = decrypt_result;
                return 0;
                break;
            }

            output_write_idx += decrypted_count;
            input_read_idx += 64;
            remaining_bytes -= 64;

            this->block_size = output_write_idx;
            if (!remaining_bytes)
                return 1;
        }
    }
    return alloc_result;
}


int CryptRSA::DataLen()
{
    return this->block_size;
}

unsigned char* CryptRSA::GetData()
{
    return this->block;
}

