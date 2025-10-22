SSLStateMachine *SSLStateMachine_new(const char *szCertificateFile, const char *szKeyFile)
{
    SSLStateMachine *pMachine = malloc(sizeof pMachine);
    int n;
    die_unless(pMachine);
    pMachine->pCtx = SSL_CTX_new(SSLv23_server_method());
    die_unless(pMachine->pCtx);
    n = SSL_CTX_use_certificate_file(pMachine->pCtx, szCertificateFile, SSL_FILETYPE_PEM);
    if (n <= 0)
    {
        SSLStateMachine_print_error(pMachine, "Error opening certificate file:");
        SSLStateMachine_free(pMachine);
        return NULL;
    }
    n = SSL_CTX_use_PrivateKey_file(pMachine->pCtx, szKeyFile, SSL_FILETYPE_PEM);
    if (n <= 0)
    {
        SSLStateMachine_print_error(pMachine, "Error opening private key file:");
        SSLStateMachine_free(pMachine);
        return NULL;
    }
    pMachine->pSSL = SSL_new(pMachine->pCtx);
    die_unless(pMachine->pSSL);
    pMachine->pbioRead = BIO_new(BIO_s_mem());
    pMachine->pbioWrite = BIO_new(BIO_s_mem());
    SSL_set_bio(pMachine->pSSL, pMachine->pbioRead, pMachine->pbioWrite);
    SSL_set_accept_state(pMachine->pSSL);
    return pMachine;
}