bool initiate_stratum(struct pool *pool)
{
    json_t *val, *res_val, *err_val, *notify_val;
    char *s, *buf, *sret = NULL;
    json_error_t err;
    bool ret = false;
    s = alloca(RECVSIZE);
    sprintf(s, "{\"id\": %d, \"method\": \"mining.subscribe\", \"params\": []}\n", pool->swork.id++);
    pool->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (pool->sock == INVSOCK)
    {
        quit(1, "Failed to create pool socket in initiate_stratum");
    }
    if (SOCKETFAIL(connect(pool->sock, (sockaddr *)pool->server, sizeof(sockaddr))))
    {
        applog(LOG_DEBUG, "Failed to connect socket to pool");
        out
    }
    if (!sock_send(pool->sock, s, strlen(s)))
    {
        applog(LOG_DEBUG, "Failed to send s in initiate_stratum");
        out
    }
    if (!sock_full(pool->sock, true))
    {
        applog(LOG_DEBUG, "Timed out waiting for response in initiate_stratum");
        out
    }
    sret = recv_line(pool->sock);
    if (!sret)
    {
        out
    }
    val = JSON_LOADS(sret, &err);
    free(sret);
    if (!val)
    {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        out
    }
    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");
    if (!res_val || json_is_null(res_val) || (err_val && !json_is_null(err_val)))
    {
        char *ss;
        if (err_val)
        {
            ss = json_dumps(err_val, JSON_INDENT(3));
        }
        else
        {
            ss = strdup("(unknown reason)");
        }
        applog(LOG_INFO, "JSON-RPC decode failed: %s", ss);
        free(ss);
        out
    }
    notify_val = json_array_get(res_val, 0);
    if (!notify_val || json_is_null(notify_val))
    {
        applog(LOG_WARNING, "Failed to parse notify_val in initiate_stratum");
        out
    }
    buf = (char *)json_string_value(json_array_get(notify_val, 0));
    if (!buf || strcasecmp(buf, "mining.notify"))
    {
        applog(LOG_WARNING, "Failed to get mining notify in initiate_stratum");
        out
    }
    pool->subscription = strdup(json_string_value(json_array_get(notify_val, 1)));
    if (!pool->subscription)
    {
        applog(LOG_WARNING, "Failed to get a subscription in initiate_stratum");
        out
    }
    pool->nonce1 = strdup(json_string_value(json_array_get(res_val, 1)));
    if (!pool->nonce1)
    {
        applog(LOG_WARNING, "Failed to get nonce1 in initiate_stratum");
        out
    }
    pool->nonce2 = json_integer_value(json_array_get(res_val, 2));
    if (!pool->nonce2)
    {
        applog(LOG_WARNING, "Failed to get nonce2 in initiate_stratum");
        out
    }
    ret = true;
    out if (val) { json_decref(val); }
    if (ret)
    {
        pool->stratum_active = true;
        pool->stratum_val = val;
        if (opt_protocol)
        {
            applog(LOG_DEBUG, "Pool %d confirmed mining.notify with subscription %s extranonce1 %s extranonce2 %d", pool->pool_no, pool->subscription, pool->nonce1, pool->nonce2);
        }
    }
    else
    {
        CLOSESOCKET(pool->sock);
    }
    return ret;
}