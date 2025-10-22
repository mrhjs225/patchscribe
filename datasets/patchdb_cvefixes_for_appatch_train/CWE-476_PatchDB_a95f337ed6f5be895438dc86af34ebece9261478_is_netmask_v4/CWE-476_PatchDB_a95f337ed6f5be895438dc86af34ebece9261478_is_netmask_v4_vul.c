unsigned char is_netmask_v4(char *ip_strv4)
{
    unsigned char netmask_v4 = 32;
    char *mask_str = NULL;
    int cidr;
    if ((mask_str = strchr(ip_strv4, '/')))
    {
        *(mask_str++) = '\0';
        if (strchr(mask_str, '.') != NULL)
        {
            return 0;
        }
        cidr = atoi(mask_str);
        if ((cidr < 0) || (cidr > 32))
        {
            return 0;
        }
        netmask_v4 = (unsigned char)cidr;
    }
    return netmask_v4;
}