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


static bool wildcard_match(const char *curr1, const char *curr2) {
    bool match = true;
    if(*curr2 == '*') {
        // wildcard match, match from back
        const char *rcurr1 = curr1 + strlen(curr1) - 1,
                   *rcurr2 = curr2 + strlen(curr2) - 1;
        while(rcurr2 > curr2 && rcurr1 > curr1)
            if(*rcurr1-- != *rcurr2--) {
                match = false;
                break;
            }
        if(match)
            if(rcurr2 != curr2)
                match = false;
            else
                while(rcurr1 >= curr1)
                    if(*rcurr1-- == '.') {
                        // not current level
                        match = false;
                        break;
                    }
    } else {
        char c1, c2;
        // evaluate both side without short-circuit
        while((bool)(c1 = *curr1++) & (bool)(c2 = *curr2++))
            if(c1 != c2) {
                match = false;
                break;
            }
        if(c1 || c2)
            match = false;
    }
    return match;
}


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
    while(fscanf(in, "%[^,]s", cfpath) != EOF) {
        // flush the unwritten data to file
        fflush(out);

        // consume the comma
        fgetc(in);

        // the input csv is in LF ending
        if(fscanf(in, "%[^\n]s", dname) == EOF) {
            fprintf(stderr, "invalid syntax\n");
            exit(EXIT_FAILURE);
        }

        // consume the LF
        fgetc(in);

        // load certificate
        BIO *cbio = BIO_new(BIO_s_file());
        if(!(BIO_read_filename(cbio, cfpath))) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        X509 *cert;
        if(!(cert = PEM_read_bio_X509(cbio, NULL, 0, NULL))) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        BIO_free_all(cbio);

        // check not before
        const ASN1_TIME *t;
        if(!(t = X509_get0_notBefore(cert))) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        ASN1_TIME *ct;
        if(!(ct = X509_time_adj(NULL, 0, NULL))) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        int day, sec;
        if(!ASN1_TIME_diff(&day, &sec, t, ct)) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if(day < 0 || sec < 0) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            ASN1_TIME_free(ct);
            X509_free(cert);
            continue;
        }

        // check not after
        if(!(t = X509_get0_notAfter(cert))) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if(!ASN1_TIME_diff(&day, &sec, t, ct)) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        ASN1_TIME_free(ct);
        if(day > 0 || sec > 0) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            X509_free(cert);
            continue;
        }

        // check RSA key length
        EVP_PKEY *pkey;
        if(!(pkey = X509_get_pubkey(cert))) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        RSA *rsa;
        if(!(rsa = EVP_PKEY_get1_RSA(pkey))) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        EVP_PKEY_free(pkey);
        // 2048 bits is 512 bytes
        if(RSA_size(rsa) < 256) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            RSA_free(rsa);
            X509_free(cert);
            continue;
        }
        RSA_free(rsa);

        BASIC_CONSTRAINTS *bc;
        if(bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL)) {
            ;
        }

        // check Subject Alternative Names
        bool match = false;
        GENERAL_NAMES *gens;
        if(gens = X509_get_ext_d2i(
            cert, NID_subject_alt_name, NULL, NULL
        )) {
            for(int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
                if(gen->type != GEN_DNS)
                    continue;
                char *cdname = gen->d.dNSName->data;
                if(match = wildcard_match(dname, cdname))
                    break;
            }
            GENERAL_NAMES_free(gens);
        }
        // check Comman Name if SANs didn't match
        if(!match) {
            X509_NAME *name = X509_get_subject_name(cert);
            int i = -1;
            while(
                (i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0
            )
                if(match = wildcard_match(dname, X509_NAME_ENTRY_get_data(
                    X509_NAME_get_entry(name, i)
                )->data))
                    break;
        }
        // both unmatch, then invalid
        if(!match) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            X509_free(cert);
            continue;
        }

        // valid certificate
        fprintf(out, "%s,%s,%u\n", cfpath, dname, 1);
        X509_free(cert);
    }

    // close file
    fclose(in);
    fclose(out);

    // deinitialise
    ERR_free_strings();
    EVP_cleanup();
}
