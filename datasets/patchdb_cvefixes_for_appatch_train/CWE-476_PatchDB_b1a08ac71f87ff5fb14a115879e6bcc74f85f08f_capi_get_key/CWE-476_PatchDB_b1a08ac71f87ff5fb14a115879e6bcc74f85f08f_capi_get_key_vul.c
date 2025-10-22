static CAPI_KEY *capi_get_key(CAPI_CTX *ctx, const TCHAR *contname, TCHAR *provname, DWORD ptype, DWORD keyspec)
{
    CAPI_KEY *key;
    DWORD dwFlags = 0;
    key = OPENSSL_malloc(sizeof(CAPI_KEY));
    if (sizeof(TCHAR) == sizeof(char))
    {
        CAPI_trace(ctx, "capi_get_key, contname=%s, provname=%s, type=%d\n", contname, provname, ptype);
    }
    if (ctx && ctx->debug_level >= CAPI_DBG_TRACE && ctx->debug_file)
    {
        char *_contname = wide_to_asc((WCHAR *)contname);
        char *_provname = wide_to_asc((WCHAR *)provname);
        CAPI_trace(ctx, "capi_get_key, contname=%s, provname=%s, type=%d\n", _contname, _provname, ptype);
        if (_provname)
        {
            OPENSSL_free(_provname);
        }
        if (_contname)
        {
            OPENSSL_free(_contname);
        }
    }
    if (ctx->store_flags & CERT_SYSTEM_STORE_LOCAL_MACHINE)
    {
        dwFlags = CRYPT_MACHINE_KEYSET;
    }
    if (!CryptAcquireContext(&key->hprov, contname, provname, ptype, dwFlags))
    {
        CAPIerr(CAPI_F_CAPI_GET_KEY, CAPI_R_CRYPTACQUIRECONTEXT_ERROR);
        capi_addlasterror();
        err
    }
    if (!CryptGetUserKey(key->hprov, keyspec, &key->key))
    {
        CAPIerr(CAPI_F_CAPI_GET_KEY, CAPI_R_GETUSERKEY_ERROR);
        capi_addlasterror();
        CryptReleaseContext(key->hprov, 0);
        err
    }
    key->keyspec = keyspec;
    key->pcert = NULL;
    return key;
    err OPENSSL_free(key);
    return NULL;
}