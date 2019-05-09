#include "common.h"

int main(int argc, char* argv[])
{
    #ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif

    if (argc < 2) {
        PRINT_AND_EXIT("Usage: client <words to send>\n");
    }

    BIO* bio = init_bio(0);
    SSL_CTX* ctx = init_context(0);

    // set trusted cert
    SSL_CTX_load_verify_locations(ctx, "./certs/server-cert.pem", NULL);
    // verify the server
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    SSL* ssl = SSL_new(ctx);
    // ssl takes ownership of bio
    SSL_set_bio(ssl, bio, bio);
    
    if (SSL_connect(ssl) != 1) {
        PRINT_AND_EXIT("SSL_connect failed\n")
    }

    char buf[1024];
    for (int i = 1; i < argc; i++) {
        // write including the null byte
        SSL_write(ssl, argv[i], strlen(argv[i]) + 1);
        int read = SSL_read(ssl, buf, sizeof(buf));
        if (read > 0) {
            printf("server says: %s\n", buf);
        }
    }
    SSL_shutdown(ssl);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    #ifdef _WIN32
    WSACleanup();
    #endif

    return 0;
}