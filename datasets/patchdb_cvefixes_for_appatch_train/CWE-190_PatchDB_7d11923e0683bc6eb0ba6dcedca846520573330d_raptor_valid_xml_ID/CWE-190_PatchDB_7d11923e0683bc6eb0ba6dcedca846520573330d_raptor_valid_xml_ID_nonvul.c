int raptor_valid_xml_ID(raptor_parser *rdf_parser, const unsigned char *string)
{
    unsigned char c;
    int len = strlen((const char *)string);
    int unichar_len;
    unsigned long unichar;
    int pos;
    for (pos = 0; (c = *string); string++, len--, pos++)
    {
        unichar_len = raptor_utf8_to_unicode_char(NULL, (const unsigned char *)string, len);
        if (unichar_len(0 || unichar_len) len)
        {
            raptor_parser_error(rdf_parser, "Bad UTF-8 encoding missing.");
            return 0;
        }
        unichar_len = raptor_utf8_to_unicode_char(&unichar, (const unsigned char *)string, len);
        if (!pos)
        {
            if (!raptor_unicode_is_namestartchar(unichar))
            {
                return 0;
            }
        }
        else
        {
            if (!raptor_unicode_is_namechar(unichar))
            {
                return 0;
            }
        }
        unichar_len--;
        string += unichar_len;
        len -= unichar_len;
    }
    return 1;
}