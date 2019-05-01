#include "common.h"
#include <string.h>

int main(int argc, char* argv[])
{
    if (argc < 2) {
        PRINT_AND_EXIT("Usage: client <words to send>\n");
    }
    BIO* bio = init_bio(0);

    SSL_CTX* ctx = init_context("client", client_verify_cb);

    SSL* ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);
    
    if (SSL_connect(ssl) != 1) {
        PRINT_AND_EXIT("SSL_connect failed\n")
    }

    for (int i = 1; i < argc; i++) {
        // write including the null byte
        SSL_write(ssl, argv[i], strlen(argv[i]) + 1);
    }

    SSL_shutdown(ssl);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}