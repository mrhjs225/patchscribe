void crcitt_string_array(char *dst, str src[], int size)
{
    register int i;
    register unsigned short ccitt;
    register char *c;
    register int len;
    int str_len;
    ccitt = 0xFFFF;
    str_len = CRC16_LEN;
    for (i = 0; i < size; i++)
    {
        if (unlikely(src[i].s == NULL))
        {
            break;
        }
        c = src[i].s;
        len = src[i].len;
        while (len)
        {
            ccitt = UPDCIT(*c, ccitt);
            c++;
            len--;
        }
    }
    ccitt = ~ccitt;
    if (int2reverse_hex(&dst, &str_len, ccitt) == -1)
    {
        LM_CRIT("string conversion incomplete\n");
    }
    while (str_len)
    {
        *dst = '0';
        dst++;
        str_len--;
    }
}