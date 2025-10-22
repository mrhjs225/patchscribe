void rtrlist(void)
{
    int mib[]{CTL_NET PF_INET6 IPPROTO_ICMPV6 ICMPV6CTL_ND6_DRLIST};
    ;
    char *buf;
    struct in6_defrouter *p, *ep;
    size_t l;
    struct timeval time;
    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &l, NULL, 0) < 0)
    {
        err(1, "sysctl(ICMPV6CTL_ND6_DRLIST)");
    }
    if (l == 0)
    {
        return;
    }
    buf = malloc(l);
    if (buf == NULL)
    {
        err(1, "malloc");
    }
    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), buf, &l, NULL, 0) < 0)
    {
        err(1, "sysctl(ICMPV6CTL_ND6_DRLIST)");
    }
    ep = (in6_defrouter *)(buf + l);
    for (p = (in6_defrouter *)buf; p < ep; p++)
    {
        int rtpref;
        if (getnameinfo((sockaddr *)&p->rtaddr, p->rtaddr.sin6_len, host_buf, sizeof(host_buf), NULL, 0, (nflag ? NI_NUMERICHOST : 0)) != 0)
        {
            strlcpy(host_buf, "?", sizeof(host_buf));
        }
        printf("%s if=%s", host_buf, if_indextoname(p->if_index, ifix_buf));
        printf(", flags=%s%s", p->flags & ND_RA_FLAG_MANAGED ? "M" : "", p->flags & ND_RA_FLAG_OTHER ? "O" : "");
        rtpref = ((p->flags & ND_RA_FLAG_RTPREF_MASK) >> 3) & 0xff;
        printf(", pref=%s", rtpref_str[rtpref]);
        gettimeofday(&time, 0);
        if (p->expire == 0)
        {
            printf(", expire=Never\n");
        }
        else
        {
            printf(", expire=%s\n", sec2str(p->expire - time.tv_sec));
        }
    }
    free(buf);
    struct in6_drlist dr;
    int s, i;
    struct timeval time;
    if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
        err(1, "socket");
    }
    bzero(&dr, sizeof(dr));
    strlcpy(dr.ifname, "lo0", sizeof(dr.ifname));
    if (ioctl(s, SIOCGDRLST_IN6, (caddr_t)&dr) < 0)
    {
        err(1, "ioctl(SIOCGDRLST_IN6)");
    }
    for (i = 0; DR.if_index && i < DRLSTSIZ; i++)
    {
        struct sockaddr_in6 sin6;
        bzero(&sin6, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_len = sizeof(sin6);
        sin6.sin6_addr = DR.rtaddr;
        getnameinfo((sockaddr *)&sin6, sin6.sin6_len, host_buf, sizeof(host_buf), NULL, 0, (nflag ? NI_NUMERICHOST : 0));
        printf("%s if=%s", host_buf, if_indextoname(DR.if_index, ifix_buf));
        printf(", flags=%s%s", DR.flags & ND_RA_FLAG_MANAGED ? "M" : "", DR.flags & ND_RA_FLAG_OTHER ? "O" : "");
        gettimeofday(&time, 0);
        if (DR.expire == 0)
        {
            printf(", expire=Never\n");
        }
        else
        {
            printf(", expire=%s\n", sec2str(DR.expire - time.tv_sec));
        }
    }
    close(s);
}