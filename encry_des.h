#ifndef _DES_H_
#define _DES_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

int des_encry(unsigned char *content, int content_len);
 
unsigned char *hex2bin(const char *data, int size, int *outlen);
 
#endif
