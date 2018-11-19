#include "encry_des.h"
char * ori_key = "original_key";//默认的密钥字符串

int des_encry(unsigned char *content, int content_len){
    DES_key_schedule ks;

    unsigned char key[8];//密钥
    unsigned char ch;//填充字符
    unsigned char tmp[8];//加密过程输入变量
    unsigned char out[8];//加密过程输出变量
    int new_len;//修改后数据长度
    int count;//数据分组组数
    int i;

    DES_string_to_key(ori_key, (DES_cblock *)key);
    DES_set_key_unchecked((const_DES_cblock*)key, &ks);

    //PKCS填充
    ch = 8 - content_len % 8;
    new_len = (content_len / 8  + 1)  * 8;
    memset(content + content_len, ch, 8 - content_len % 8);

    count = new_len / 8;
    for (i = 0; i < count; i++){
        memcpy(tmp, content + 8 * i, 8);
        DES_ecb_encrypt((const_DES_cblock*)tmp, (DES_cblock*)out, &ks, DES_ENCRYPT);
        memcpy(content + 8 * i, out, 8);
    }

    return new_len;
}