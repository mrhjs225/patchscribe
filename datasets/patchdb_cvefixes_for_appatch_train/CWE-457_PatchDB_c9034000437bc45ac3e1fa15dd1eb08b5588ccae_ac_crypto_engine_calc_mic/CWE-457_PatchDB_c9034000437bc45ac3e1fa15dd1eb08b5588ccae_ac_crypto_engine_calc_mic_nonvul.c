EXPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t *engine, const uint8_t eapol[256], const uint32_t eapol_size, uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20], const uint8_t keyver, const int vectorIdx, const int threadid)
{
    uint8_t *ptk = engine->thread_data[threadid]->ptk;
    if (keyver == 1)
    {
        HMAC(EVP_md5(), &ptk[vectorIdx], 16, eapol, eapol_size, mic[vectorIdx], NULL);
    }
    if (keyver == 2)
    {
        HMAC(EVP_sha1(), &ptk[vectorIdx], 16, eapol, eapol_size, mic[vectorIdx], NULL);
    }
    if (keyver == 3)
    {
        size_t miclen = 16;
        CMAC_CTX *ctx = NULL;
        ctx = CMAC_CTX_new();
        CMAC_Init(ctx, ptk, 16, EVP_aes_128_cbc(), 0);
        CMAC_Update(ctx, eapol, eapol_size);
        CMAC_Final(ctx, mic[vectorIdx], &miclen);
        CMAC_CTX_free(ctx);
    }
    if (keyver == 3)
    {
        fprintf(stderr, "Key version %d is only supported when OpenSSL (or similar) supports CMAC.\n", keyver);
        abort();
    }
    else
    {
        fprintf(stderr, "Unsupported key version %d encountered.\n", keyver);
        abort();
    }
}