int mp_init(mp_int *a)
{
    int i;
    a->dp = OPT_CAST() XMALLOC(sizeof(mp_digit) * MP_PREC, 0, DYNAMIC_TYPE_BIGINT);
    if (a->dp == NULL)
    {
        return MP_MEM;
    }
    for (i = 0; i < MP_PREC; i++)
    {
        a->dp[i] = 0;
    }
    a->used = 0;
    a->alloc = MP_PREC;
    a->sign = MP_ZPOS;
    return MP_OKAY;
}