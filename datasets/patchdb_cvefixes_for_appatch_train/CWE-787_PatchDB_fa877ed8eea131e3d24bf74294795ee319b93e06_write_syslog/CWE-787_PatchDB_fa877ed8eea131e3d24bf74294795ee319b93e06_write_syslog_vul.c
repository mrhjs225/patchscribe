static void write_syslog(int level, const char *line)
{
    static bool openlog_done = false;
    static unsigned long seq = 0;
    static int syslog_fac = LOG_LOCAL0;
    int len = strlen(line);
    if (Use_syslog == 0)
    {
        return;
    }
    if (!openlog_done)
    {
        if (strcasecmp(Syslog_facility, "LOCAL0") == 0)
        {
            syslog_fac = LOG_LOCAL0;
        }
        if (strcasecmp(Syslog_facility, "LOCAL1") == 0)
        {
            syslog_fac = LOG_LOCAL1;
        }
        if (strcasecmp(Syslog_facility, "LOCAL2") == 0)
        {
            syslog_fac = LOG_LOCAL2;
        }
        if (strcasecmp(Syslog_facility, "LOCAL3") == 0)
        {
            syslog_fac = LOG_LOCAL3;
        }
        if (strcasecmp(Syslog_facility, "LOCAL4") == 0)
        {
            syslog_fac = LOG_LOCAL4;
        }
        if (strcasecmp(Syslog_facility, "LOCAL5") == 0)
        {
            syslog_fac = LOG_LOCAL5;
        }
        if (strcasecmp(Syslog_facility, "LOCAL6") == 0)
        {
            syslog_fac = LOG_LOCAL6;
        }
        if (strcasecmp(Syslog_facility, "LOCAL7") == 0)
        {
            syslog_fac = LOG_LOCAL7;
        }
        openlog(Syslog_ident, LOG_PID | LOG_NDELAY, syslog_fac);
        openlog_done = true;
    }
    seq++;
    if (len > PG_SYSLOG_LIMIT || strchr(line, '\n') != NULL)
    {
        int chunk_nr = 0;
        while (len > 0)
        {
            char buf[PG_SYSLOG_LIMIT + 1];
            int buflen;
            int l;
            int i;
            if (line[0] == '\n')
            {
                line++;
                len--;
                continue;
            }
            strncpy(buf, line, PG_SYSLOG_LIMIT);
            buf[PG_SYSLOG_LIMIT] = '\0';
            if (strchr(buf, '\n') != NULL)
            {
                *strchr(buf, '\n') = '\0';
            }
            l = strlen(buf);
            buflen = pg_mbcliplen(buf, l, l);
            buf[buflen] = '\0';
            l = strlen(buf);
            if (isspace((unsigned char)line[l]) || line[l] == '\0')
            {
                buflen = l;
            }
            else
            {
                i = l - 1;
                while (i > 0 && !isspace((unsigned char)buf[i]))
                {
                    i--;
                }
                if (i <= 0)
                {
                    buflen = l;
                }
                else
                {
                    buflen = i;
                    buf[i] = '\0';
                }
            }
            chunk_nr++;
            syslog(level, "[%lu-%d] %s", seq, chunk_nr, buf);
            line += buflen;
            len -= buflen;
        }
    }
    else
    {
        syslog(level, "[%lu] %s", seq, line);
    }
}