#include <iostream>
#include <fstream>
#include <sstream>
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
using namespace std;


int main(int argc, char* argv[])
{
    if (argc != 2){
        cerr << "/path/to/encrypted" << endl;
        return 1;
    }

    ifstream infile(argv[1]);
    std::stringstream z;

    if (!infile) {
        cerr << "Can't open file: " << argv[1] << endl;
        return 3;
    }

    infile.seekg(0, infile.end);
    size_t inlen = infile.tellg();
    infile.seekg(0, infile.beg);
    mbedtls_aes_context ctx;
    unsigned char iv[16] = { 0x11, 0x22, 0xed, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    unsigned char key[16] =  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t inblock_size = 16;
    unsigned char input[inblock_size];
    unsigned char output[inblock_size];
    unsigned char hash_output[64];
    mbedtls_sha512_context ct;
    mbedtls_sha512_init( &ct );
    mbedtls_sha512_starts( &ct, 0 );
    mbedtls_aes_init( &ctx );

    mbedtls_aes_setkey_dec(&ctx, key, 128);

    for (int i = 0; inlen - i >= 1; i = i+inblock_size) {
        infile.read((char*)input, inblock_size);
        mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, inblock_size, iv, input, output);
        z.write((char*)output, inblock_size);
    }

    std::cout << z.str();

    return 0;
}
