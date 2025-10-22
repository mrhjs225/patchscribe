int mp_copy(mp_int *a, mp_int *b)
{
    int res, n;
    if (a == b)
    {
        return MP_OKAY;
    }
    if (b->alloc < a->used)
    {
        if ((res = mp_grow(b, a->used)) != MP_OKAY)
        {
            return res;
        }
    }
    {
        register mp_digit *tmpa, *tmpb;
        tmpa = a->dp;
        tmpb = b->dp;
        for (n = 0; n < a->used; n++)
        {
            *tmpb++ = *tmpa++;
        }
        for (; n < b->used; n++)
        {
            *tmpb++ = 0;
        }
    }
    b->used = a->used;
    b->sign = a->sign;
    return MP_OKAY;
}