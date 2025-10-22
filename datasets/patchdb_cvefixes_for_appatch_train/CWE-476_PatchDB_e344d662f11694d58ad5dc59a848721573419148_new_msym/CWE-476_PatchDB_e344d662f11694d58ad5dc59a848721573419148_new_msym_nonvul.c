static inline int new_msym(codegen_scope *s, mrb_sym sym)
{
    size_t i, len;
    if (s->irep == NULL)
    {
        return 0;
    }
    len = s->irep->slen;
    if (len > 256)
    {
        len = 256;
    }
    for (i = 0; i < len; i++)
    {
        if (s->irep->syms[i] == sym)
        {
            return i;
        }
        if (s->irep->syms[i] == 0)
        {
            break;
        }
    }
    if (i == 256)
    {
        codegen_error(s, "too many symbols (max 256)");
    }
    s->irep->syms[i] = sym;
    if (i == s->irep->slen)
    {
        s->irep->slen++;
    }
    return i;
}