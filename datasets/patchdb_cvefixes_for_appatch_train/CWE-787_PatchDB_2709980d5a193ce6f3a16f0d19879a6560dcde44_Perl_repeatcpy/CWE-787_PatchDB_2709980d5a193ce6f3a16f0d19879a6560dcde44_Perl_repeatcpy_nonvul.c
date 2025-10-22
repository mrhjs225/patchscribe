void Perl_repeatcpy(register char *to, register const char *from, I32 len, register IV count)
{
    PERL_ARGS_ASSERT_REPEATCPY;
    if (count < 0)
    {
        Perl_croak_nocontext("%s", PL_memory_wrap);
    }
    if (len == 1)
    {
        memset(to, *from, count);
    }
    if (count)
    {
        char *p = to;
        IV items, linear, half;
        linear = count < PERL_REPEATCPY_LINEAR ? count : PERL_REPEATCPY_LINEAR;
        for (items = 0; items < linear; ++items)
        {
            const char *q = from;
            IV todo;
            for (todo = len; todo > 0; todo--)
            {
                *p++ = *q++;
            }
        }
        half = count / 2;
        while (items <= half)
        {
            IV size = items * len;
            memcpy(p, to, size);
            p += size;
            items *= 2;
        }
        if (count > items)
        {
            memcpy(p, to, (count - items) * len);
        }
    }
}