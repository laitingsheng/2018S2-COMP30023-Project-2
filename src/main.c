#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Please provide a path to the certificate\n");
        return 0;
    }

    // initialise OpenSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    SSL_load_error_strings();

    // open file
    FILE *in = fopen(argv[1], "r"), *out = fopen("output.csv", "w");

    char cfpath[1024], dname[1024];
    BIO *cbio;
    X509 *cert;
    X509_NAME *cert_issuer;
    while(fscanf(in, "%[^,]s", cfpath) != EOF) {
        // consume the comma
        fgetc(in);

        // the input csv is in LF ending
        if(fscanf(in, "%[^\n]s", dname) == EOF) {
            fprintf(stderr, "invalid syntax\n");
            exit(EXIT_FAILURE);
        }

        // consume the LF
        fgetc(in);

        cbio = BIO_new(BIO_s_file());
        if(!(BIO_read_filename(cbio, cfpath))) {
            ERR_print_errors_fp(stderr);
            BIO_free_all(cbio);
            exit(EXIT_FAILURE);
        }
        if(!(cert = PEM_read_bio_X509(cbio, NULL, 0, NULL))) {
            ERR_print_errors_fp(stderr);
            BIO_free_all(cbio);
            exit(EXIT_FAILURE);
        }
        BIO_free_all(cbio);
    }

    // close file
    fclose(in);
    fclose(out);

    // deinitialise
    ERR_free_strings();
    EVP_cleanup();
}
