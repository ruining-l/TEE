#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

// AES-XTS 加密函数
int aes_xts_encrypt(const unsigned char *key1, const unsigned char *plaintext, size_t plaintext_len, unsigned char *TEE_SBUFFER) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // 创建和初始化加密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return 0;
    }

    // 初始化加密操作
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key1, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 加密消息
    if (1 != EVP_EncryptUpdate(ctx, TEE_SBUFFER, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;

    // 完成加密
    if (1 != EVP_EncryptFinal_ex(ctx, TEE_SBUFFER + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    // 清理加密上下文
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES-XTS 解密函数
int aes_xts_decrypt(const unsigned char *key1, const unsigned char *TEE_SBUFFER, size_t ciphertext_len, unsigned char *GEN_SBUFFER) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // 创建和初始化解密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return 0;
    }

    // 初始化解密操作
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key1, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 解密消息
    if (1 != EVP_DecryptUpdate(ctx, GEN_SBUFFER, &len, TEE_SBUFFER, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    // 完成解密
    if (1 != EVP_DecryptFinal_ex(ctx, GEN_SBUFFER + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    // 清理解密上下文
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// AES-GCM 加密函数
int aes_gcm_encrypt(const unsigned char *key2, const unsigned char *plaintext, size_t plaintext_len, unsigned char *GEN_BUFFER, unsigned char *auth_tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char tag[16];

    // 创建和初始化加密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return 0;
    }

    // 初始化加密操作
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key2, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 加密消息
    if (1 != EVP_EncryptUpdate(ctx, GEN_BUFFER, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;

    // 设置附加认证数据（AAD）
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, 0)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 完成加密
    if (1 != EVP_EncryptFinal_ex(ctx, GEN_BUFFER + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    // 获取认证标签
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    memcpy(auth_tag, tag, 16);

    // 清理加密上下文
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES-GCM 解密函数
int aes_gcm_decrypt(const unsigned char *key2, const unsigned char *GEN_BUFFER, size_t ciphertext_len, const unsigned char *auth_tag, unsigned char *GEN_CBUFFER) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // 创建和初始化解密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return 0;
    }

    // 初始化解密操作
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key2, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 解密消息
    if (1 != EVP_DecryptUpdate(ctx, GEN_CBUFFER, &len, GEN_BUFFER, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    // 设置认证标签
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)auth_tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // 完成解密
    if (1 != EVP_DecryptFinal_ex(ctx, GEN_CBUFFER + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    // 清理解密上下文
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// 服务器端主函数
int server_main() {
    unsigned char key1[32]; // AES-XTS 密钥
    unsigned char key2[32]; // AES-GCM 密钥
    unsigned char plaintext[] = "Hello, client!";
    unsigned char TEE_SBUFFER[128]; // 加密后的数据
    unsigned char GEN_SBUFFER[128]; // 解密后的数据
    unsigned char GEN_BUFFER[128]; // 传输给客户端的数据
    unsigned char auth_tag[16]; // 认证标签

    // 填充密钥
    RAND_bytes(key1, sizeof(key1));
    RAND_bytes(key2, sizeof(key2));

    // AES-XTS 加密
    aes_xts_encrypt(key1, plaintext, sizeof(plaintext), TEE_SBUFFER);

    // AES-XTS 解密
    aes_xts_decrypt(key1, TEE_SBUFFER, sizeof(TEE_SBUFFER), GEN_SBUFFER);

    // AES-GCM 加密
    aes_gcm_encrypt(key2, GEN_SBUFFER, sizeof(GEN_SBUFFER), GEN_BUFFER, auth_tag);

    // 这里应该有代码将 GEN_BUFFER 和 auth_tag 发送给客户端

    // 清理
    memset(key1, 0, sizeof(key1));
    memset(key2, 0, sizeof(key2));
    memset(TEE_SBUFFER, 0, sizeof(TEE_SBUFFER));
    memset(GEN_SBUFFER, 0, sizeof(GEN_SBUFFER));
    memset(GEN_BUFFER, 0, sizeof(GEN_BUFFER));
    memset(auth_tag, 0, sizeof(auth_tag));

    return 0;
}

// 客户端主函数
int client_main() {
    unsigned char key2[32]; // AES-GCM 密钥
    unsigned char key3[32]; // AES-XTS 密钥
    unsigned char GEN_CBUFFER[128]; // 客户端解密后的数据
    unsigned char TEE_CBUFFER[128]; // 客户端加密后的数据
    unsigned char auth_tag[16]; // 认证标签

    // 填充密钥
    RAND_bytes(key2, sizeof(key2));
    RAND_bytes(key3, sizeof(key3));

    // 这里应该有代码从服务器接收 GEN_BUFFER 和 auth_tag

    // AES-GCM 解密
    aes_gcm_decrypt(key2, GEN_BUFFER, sizeof(GEN_BUFFER), auth_tag, GEN_CBUFFER);

    // AES-XTS 加密
    aes_xts_encrypt(key3, GEN_CBUFFER, sizeof(GEN_CBUFFER), TEE_CBUFFER);

    // 清理
    memset(key2, 0, sizeof(key2));
    memset(key3, 0, sizeof(key3));
    memset(GEN_CBUFFER, 0, sizeof(GEN_CBUFFER));
    memset(TEE_CBUFFER, 0, sizeof(TEE_CBUFFER));
    memset(auth_tag, 0, sizeof(auth_tag));

    return 0;
}

int main() {
    // 根据实际情况选择运行服务器端或客户端
    server_main();
    // client_main();

    return 0;
}