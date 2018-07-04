#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
using namespace std;


int main(int argc, char* argv[])
{
    if (argc != 3){
        cerr << "password /path/to/encrypted" << endl;
        return 1;
    }

    ifstream infile(argv[2]);
    std::stringstream z;
    std::stringstream h;

    if (!infile) {
        cerr << "Can't open file: " << argv[2] << endl;
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

    for (int i = 0; i < 16 && i < strlen(argv[1]); i++) {
        key[i] = argv[1][i];
    }

    mbedtls_aes_setkey_dec(&ctx, key, 128);

    for (int i = 0; inlen - i > 64 + inblock_size; i = i+inblock_size) {
        infile.read((char*)input, inblock_size);
        mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, inblock_size, iv, input, output);
        mbedtls_sha512_update( &ct, output, inblock_size );
        z.write((char*)output, inblock_size);
    }

    infile.read((char*)input, inblock_size);
    mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, inblock_size, iv, input, output);
    mbedtls_sha512_update( &ct, output, inblock_size );


    int i = inblock_size - 1;
    for (; i >= 0; i--) {
        if (output[i] != 0x01) {
            break;
        }
    }

    z.write((char*)output, i+1);
    mbedtls_sha512_finish( &ct, hash_output );
    unsigned char given_hash[64];
    infile.read((char*)given_hash, 64);

    for (size_t i = 0; i < 64; ++i){
        if (given_hash[i] != hash_output[i]){
            cerr << "nok, damaged message" << endl;
            break;
        }
    }
    cout << "\nok" << endl;
    cout << z.str();



    return 0;
}
