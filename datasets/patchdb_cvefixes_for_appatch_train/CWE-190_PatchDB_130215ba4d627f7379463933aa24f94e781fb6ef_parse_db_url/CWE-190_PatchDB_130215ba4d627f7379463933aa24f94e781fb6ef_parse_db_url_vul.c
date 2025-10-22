static int parse_db_url(struct db_id *id, const char *url)
{
    state { ST_SCHEME, ST_SLASH1, ST_SLASH2, ST_USER_HOST, ST_PASS_PORT, ST_HOST, ST_PORT, ST_DB }
    enum state st;
    int len, i;
    const char *begin;
    char *prev_token;
    prev_token = 0;
    if (!id || !url)
    {
        err
    }
    len = strlen(url);
    if (len < SHORTEST_DB_URL_LEN)
    {
        err
    }
    memset(id, 0, sizeof(db_id));
    st = ST_SCHEME;
    begin = url;
    for (i = 0; i < len; i++)
    {
        switch (st)
        {
        case ST_SCHEME:
            switch (url[i])
            {
            case ':':
                st = ST_SLASH1;
                if (dupl_string(&id->scheme, begin, url + i) < 0)
                {
                    err
                }
                break;
            }
            break;
        case ST_SLASH1:
            switch (url[i])
            {
            case '/':
                st = ST_SLASH2;
                break;
            default:
                err
            }
            break;
        case ST_SLASH2:
            switch (url[i])
            {
            case '/':
                st = ST_USER_HOST;
                begin = url + i + 1;
                break;
            default:
                err
            }
            break;
        case ST_USER_HOST:
            switch (url[i])
            {
            case '@':
                st = ST_HOST;
                if (dupl_string(&id->username, begin, url + i) < 0)
                {
                    err
                }
                begin = url + i + 1;
                break;
            case ':':
                st = ST_PASS_PORT;
                if (dupl_string(&prev_token, begin, url + i) < 0)
                {
                    err
                }
                begin = url + i + 1;
                break;
            case '/':
                if (dupl_string(&id->host, begin, url + i) < 0)
                {
                    err
                }
                if (dupl_string(&id->database, url + i + 1, url + len) < 0)
                {
                    err
                }
                return 0;
            }
            break;
        case ST_PASS_PORT:
            switch (url[i])
            {
            case '@':
                st = ST_HOST;
                id->username = prev_token;
                if (dupl_string(&id->password, begin, url + i) < 0)
                {
                    err
                }
                begin = url + i + 1;
                break;
            case '/':
                id->host = prev_token;
                id->port = str2s(begin, url + i - begin, 0);
                if (dupl_string(&id->database, url + i + 1, url + len) < 0)
                {
                    err
                }
                return 0;
            }
            break;
        case ST_HOST:
            switch (url[i])
            {
            case ':':
                st = ST_PORT;
                if (dupl_string(&id->host, begin, url + i) < 0)
                {
                    err
                }
                begin = url + i + 1;
                break;
            case '/':
                if (dupl_string(&id->host, begin, url + i) < 0)
                {
                    err
                }
                if (dupl_string(&id->database, url + i + 1, url + len) < 0)
                {
                    err
                }
                return 0;
            }
            break;
        case ST_PORT:
            switch (url[i])
            {
            case '/':
                id->port = str2s(begin, url + i - begin, 0);
                if (dupl_string(&id->database, url + i + 1, url + len) < 0)
                {
                    err
                }
                return 0;
            }
            break;
        case ST_DB:
            break;
        }
    }
    if (st != ST_DB)
    {
        err
    }
    return 0;
    err if (id->scheme) { pkg_free(id->scheme); }
    if (id->username)
    {
        pkg_free(id->username);
    }
    if (id->password)
    {
        pkg_free(id->password);
    }
    if (id->host)
    {
        pkg_free(id->host);
    }
    if (id->database)
    {
        pkg_free(id->database);
    }
    if (prev_token)
    {
        pkg_free(prev_token);
    }
    return -1;
}