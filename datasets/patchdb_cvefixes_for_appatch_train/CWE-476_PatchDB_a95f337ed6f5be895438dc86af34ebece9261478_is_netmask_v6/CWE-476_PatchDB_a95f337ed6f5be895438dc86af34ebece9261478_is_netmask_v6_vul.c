unsigned char is_netmask_v6(char *ip_strv6)
{
    unsigned char netmask_v6 = 128;
    char *mask_str = NULL;
    int cidr;
    if ((mask_str = strchr(ip_strv6, '/')))
    {
        *(mask_str++) = '\0';
        if (strchr(mask_str, '.') != NULL)
        {
            return 0;
        }
        cidr = atoi(mask_str);
        if ((cidr < 0) || (cidr > 64))
        {
            return 0;
        }
        netmask_v6 = (unsigned char)cidr;
    }
    return netmask_v6;
}