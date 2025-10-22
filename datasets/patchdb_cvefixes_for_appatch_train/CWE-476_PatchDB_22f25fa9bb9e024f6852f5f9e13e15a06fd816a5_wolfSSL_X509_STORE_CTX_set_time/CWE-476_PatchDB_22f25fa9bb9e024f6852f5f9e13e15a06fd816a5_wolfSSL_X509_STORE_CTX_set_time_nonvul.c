void wolfSSL_X509_STORE_CTX_set_time(WOLFSSL_X509_STORE_CTX *ctx, unsigned long flags, time_t t)
{
    (void)flags;
    if (ctx == NULL)
    {
        return;
    }
    ctx->param->check_time = t;
    ctx->param->flags |= WOLFSSL_USE_CHECK_TIME;
}