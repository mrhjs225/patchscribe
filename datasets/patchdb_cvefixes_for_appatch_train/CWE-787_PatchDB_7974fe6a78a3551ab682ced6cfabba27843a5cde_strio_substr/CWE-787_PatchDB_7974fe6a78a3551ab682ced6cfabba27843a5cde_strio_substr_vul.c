static VALUE strio_substr(struct StringIO *ptr, long pos, long len)
{
    VALUE str = ptr->string;
    rb_encoding *enc = rb_enc_get(str);
    long rlen = RSTRING_LEN(str) - pos;
    if (len > rlen)
    {
        len = rlen;
    }
    if (len < 0)
    {
        len = 0;
    }
    return rb_enc_str_new(RSTRING_PTR(str) + pos, len, enc);
}