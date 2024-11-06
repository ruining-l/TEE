#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//AES-XTS和AES-GCM函数定义
// AES-XTS 加密函数
int aes_xts_encrypt(unsigned char *key1, unsigned char *plaintext, size_t plaintext_len, unsigned char *TEE_SBUFFER) {
    AES_KEY enc_key, dec_key;
    unsigned char tweak[AES_BLOCK_SIZE];
    memset(tweak, 0, AES_BLOCK_SIZE); // 初始化tweak为0

    // 设置加密和解密密钥
    AES_set_encrypt_key(key1, 256, &enc_key);
    AES_set_decrypt_key(key1, 256, &dec_key);

    // 加密数据
    for (size_t i = 0; i < plaintext_len; i += AES_BLOCK_SIZE) {
        AES_encrypt(tweak, tweak, &enc_key); // 加密tweak
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            TEE_SBUFFER[i + j] = plaintext[i + j] ^ tweak[j];
        }
        // 更新tweak
        for (int j = 0; j < AES_BLOCK_SIZE - 1; j++) {
            if (tweak[j] == 0xFF) {
                tweak[j] = 0;
            } else {
                tweak[j]++;
                break;
            }
        }
        tweak[AES_BLOCK_SIZE - 1]++;
    }
    return 0;
}

// AES-XTS 解密函数
int aes_xts_decrypt(unsigned char *key1, unsigned char *TEE_SBUFFER, size_t TEE_SBUFFER_len, unsigned char *GEN_SBUFFER) {
    AES_KEY enc_key, dec_key;
    unsigned char tweak[AES_BLOCK_SIZE];
    memset(tweak, 0, AES_BLOCK_SIZE); // 初始化tweak为0

    // 设置加密和解密密钥
    AES_set_encrypt_key(key1, 256, &enc_key);
    AES_set_decrypt_key(key1, 256, &dec_key);

    // 解密数据
    for (size_t i = 0; i < TEE_SBUFFER_len; i += AES_BLOCK_SIZE) {
        AES_encrypt(tweak, tweak, &enc_key); // 加密tweak
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            GEN_SBUFFER[i + j] = TEE_SBUFFER[i + j] ^ tweak[j];
        }
        // 更新tweak
        for (int j = 0; j < AES_BLOCK_SIZE - 1; j++) {
            if (tweak[j] == 0xFF) {
                tweak[j] = 0;
            } else {
                tweak[j]++;
                break;
            }
        }
        tweak[AES_BLOCK_SIZE - 1]++;
    }
    return 0;
}

// AES-GCM 加密函数
int aes_gcm_encrypt(unsigned char *key2, unsigned char *plaintext, size_t plaintext_len, unsigned char *GEN_BUFFER, unsigned char *auth_tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // 创建和初始化加密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating cipher context\n");
        return 0;
    }

    // 初始化加密操作
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key2, NULL)) {
        fprintf(stderr, "Error initializing encryption\n");
        return 0;
    }

    // 加密消息
    if (1 != EVP_EncryptUpdate(ctx, GEN_BUFFER, &len, plaintext, plaintext_len)) {
        fprintf(stderr, "Error encrypting plaintext\n");
        return 0;
    }

    // 完成加密
    if (1 != EVP_EncryptFinal_ex(ctx, GEN_BUFFER + len, &len)) {
        fprintf(stderr, "Error finalizing encryption\n");
        return 0;
    }
    ciphertext_len = len;

    // 获取认证标签
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag)) {
        fprintf(stderr, "Error getting tag\n");
        return 0;
    }

    // 清理加密上下文
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES-GCM 解密函数
int aes_gcm_decrypt(unsigned char *key2, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *GEN_CBUFFER, unsigned char *auth_tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // 创建和初始化解密上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating cipher context\n");
        return 0;
    }

    // 初始化解密操作
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key2, NULL)) {
        fprintf(stderr, "Error initializing decryption\n");
        return 0;
    }

    // 设置认证标签
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, auth_tag)) {
        fprintf(stderr, "Error setting tag\n");
        return 0;
    }

    // 解密消息
    if (1 != EVP_DecryptUpdate(ctx, GEN_CBUFFER, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Error decrypting ciphertext\n");
        return 0;
    }

    plaintext_len = len;

    // 完成解密
    if (1 != EVP_DecryptFinal_ex(ctx, GEN_CBUFFER + len, &len)) {
        fprintf(stderr, "Error finalizing decryption\n");
        return 0;
    }
    plaintext_len += len;

    // 清理解密上下文
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    unsigned char key1[32] = "0123456789abcdef0123456789abcdef"; // 256位密钥
    unsigned char key2[32] = "fedcba9876543210fedcba9876543210"; // 256位密钥
    unsigned char TEE_SBUFFER[256];
    unsigned char GEN_BUFFER[256];
    unsigned char auth_tag[16];

    // 创建socket文件描述符
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 绑定socket到端口8080
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 监听端口
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // 接受客户端连接
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // 读取客户端发送的数据
    read(new_socket, buffer, BUFFER_SIZE);
    printf("Message received: %s\n", buffer);

    // 服务器端加密流程
    aes_xts_encrypt(key1, (unsigned char*)buffer, strlen(buffer), TEE_SBUFFER);
    int len = aes_gcm_encrypt(key2, TEE_SBUFFER, strlen((char*)TEE_SBUFFER), GEN_BUFFER, auth_tag);

    // 发送加密后的数据和认证标签
    send(new_socket, GEN_BUFFER, len, 0);
    send(new_socket, auth_tag, 16, 0);

    // 关闭socket
    close(new_socket);
    close(server_fd);

    return 0;
}