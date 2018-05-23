#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


static bool wildcard_match(const char * restrict curr1,
                           const char * restrict curr2) {
    bool match = true;
    if(*curr2 == '*')
        // since the wildcard will only appears in the front by itself, then
        // find the first . in each string, then compare the rest, and avoid a
        // ill-formed domain such as (nil).example.com matching with
        // *.example.com
        match = *curr1 != '.' &&
                !strcmp(strchr(curr1, '.'), strchr(curr2, '.'));
    else
        // just compare the domain without any wildcard
        match = !strcmp(curr1, curr2);
    return match;
}


int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Please provide a path to the certificate\n");
        return 0;
    }

    // initialise OpenSSL, with respect to a specific version
#ifdef DEBUG
    fprintf(stderr, "version is %lx\n", OPENSSL_VERSION_NUMBER);
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L // any versions prior to 1.1.0
    SSL_library_init();
#ifdef DEBUG
    fprintf(stderr, "version prior to 1.1\n");
#endif
#else // 1.1.0
    OPENSSL_init_ssl(0, NULL);
#ifdef DEBUG
    fprintf(stderr, "version 1.1\n");
#endif
#endif
    SSL_load_error_strings();

    // open file
    FILE *in = fopen(argv[1], "r"), *out = fopen("output.csv", "w");

    char cfpath[1024], dname[1024];
#ifdef DEBUG
    int count = 0;
#endif
    while(fscanf(in, "%[^,]s", cfpath) != EOF) {
#ifdef DEBUG
        fprintf(stderr, "Line %d:\n", ++count);
#endif
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

#ifdef DEBUG
        fprintf(stderr, "  %s, %s\n", cfpath, dname);
#endif

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

#ifdef DEBUG
        fprintf(stderr, "    successfully loaded\n");
#endif

        // check not before
        const ASN1_TIME *t;
#if OPENSSL_VERSION_NUMBER < 0x10100000L // any versions prior to 1.1.0
        if(!(t = X509_get_notBefore(cert))) {
#else // 1.1.0
        if(!(t = X509_get0_notBefore(cert))) {
#endif
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
#ifdef DEBUG
        fprintf(stderr, "        values: %d, %d\n", day, sec);
#endif
        // current time is earlier than the time specified
        if(day < 0 || sec < 0) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            ASN1_TIME_free(ct);
            X509_free(cert);
            continue;
        }

#ifdef DEBUG
        fprintf(stderr, "    pass Not Before\n");
#endif

        // check not after
#if OPENSSL_VERSION_NUMBER < 0x10100000L // any versions prior to 1.1.0
        if(!(t = X509_get_notAfter(cert))) {
#else // 1.1.0
        if(!(t = X509_get0_notAfter(cert))) {
#endif
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if(!ASN1_TIME_diff(&day, &sec, t, ct)) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        ASN1_TIME_free(ct);
#ifdef DEBUG
        fprintf(stderr, "        values: %d, %d\n", day, sec);
#endif
        // current time is later than the time specified
        if(day > 0 || sec > 0) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            X509_free(cert);
            continue;
        }

#ifdef DEBUG
        fprintf(stderr, "    pass Not After\n");
#endif

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
#ifdef DEBUG
        fprintf(stderr, "        values: %d\n", RSA_size(rsa));
#endif
        EVP_PKEY_free(pkey);
        // 2048 bits is 256 bytes
        if(RSA_size(rsa) < 256) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            RSA_free(rsa);
            X509_free(cert);
            continue;
        }
        RSA_free(rsa);

#ifdef DEBUG
        fprintf(stderr, "    pass RSA key length\n");
#endif

        // validate basic constraints
        BASIC_CONSTRAINTS *bc;
        bool match = false;
        if(bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL))
#ifdef DEBUG
        {
            fprintf(stderr, "        values: %d\n", bc->ca);
#endif
            match = !bc->ca;
#ifdef DEBUG
        }
#endif
        if(!match) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            BASIC_CONSTRAINTS_free(bc);
            X509_free(cert);
            continue;
        }
        BASIC_CONSTRAINTS_free(bc);

#ifdef DEBUG
        fprintf(stderr, "    pass Basic Constraints\n");
#endif

        // validate extended key usage
        int i = -1;
        match = false;
        STACK_OF(ASN1_OBJECT) *objs;
        if(objs = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL)) {
            for(int i = 0; i < sk_ASN1_OBJECT_num(objs); ++i)
#ifdef DEBUG
            {
                int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(objs, i));
                fprintf(stderr, "        value: %d\n", nid);
                match = match || nid == NID_server_auth;
            }
#else
                if(match = OBJ_obj2nid(
                    sk_ASN1_OBJECT_value(objs, i)
                ) == NID_server_auth)
                    break;
#endif
            sk_ASN1_OBJECT_pop_free(objs, ASN1_OBJECT_free);
        }
        if(!match) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            X509_free(cert);
            continue;
        }

#ifdef DEBUG
        fprintf(stderr, "    pass Extended Key Usage\n");
#endif

        // check Subject Alternative Names (if applicable)
        match = false;
        GENERAL_NAMES *gens;
        if(gens = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL)) {
            for(int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
                if(gen->type != GEN_DNS)
                    continue;
#ifdef DEBUG
                char *cdname = gen->d.dNSName->data;
                fprintf(stderr, "        SAN values: %s\n", cdname);
                match = match || wildcard_match(dname, cdname);
#else
                if(match = wildcard_match(dname, gen->d.dNSName->data))
                    break;
#endif
            }
            GENERAL_NAMES_free(gens);
        }
        // check Comman Name (if applicable) if SANs didn't match
#ifdef DEBUG
        if(true) {
#else
        if(!match) {
#endif
            X509_NAME *name = X509_get_subject_name(cert);
            int i = -1;
            while(
                (i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0
            )
#ifdef DEBUG
            {
                char *cdname = X509_NAME_ENTRY_get_data(
                    X509_NAME_get_entry(name, i)
                )->data;
                fprintf(stderr, "        CN values: %s\n", cdname);
                match = match || wildcard_match(dname, cdname);
            }
#else
                if(match = wildcard_match(dname, X509_NAME_ENTRY_get_data(
                    X509_NAME_get_entry(name, i)
                )->data))
                    break;
#endif
        }
        // both unmatch, then invalid
        if(!match) {
            fprintf(out, "%s,%s,%d\n", cfpath, dname, 0);
            X509_free(cert);
            continue;
        }

#ifdef DEBUG
        fprintf(stderr, "    pass Domain Name check by SAN and CN\n");
#endif

        // valid certificate
        fprintf(out, "%s,%s,%u\n", cfpath, dname, 1);

#ifdef DEBUG
        fprintf(stderr, "    pass all test\n");
#endif

        X509_free(cert);
    }

    // close file
    fclose(in);
    fclose(out);

    // deinitialise
    ERR_free_strings();
    EVP_cleanup();
}
