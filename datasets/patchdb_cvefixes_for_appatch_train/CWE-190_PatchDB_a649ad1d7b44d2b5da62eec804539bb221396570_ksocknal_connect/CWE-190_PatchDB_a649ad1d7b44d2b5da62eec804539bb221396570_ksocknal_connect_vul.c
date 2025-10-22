int ksocknal_connect(ksock_route_t *route)
{
    LIST_HEAD(zombies);
    ksock_peer_t *peer = route->ksnr_peer;
    int type;
    int wanted;
    struct socket *sock;
    cfs_time_t deadline;
    int retry_later = 0;
    int rc = 0;
    deadline = cfs_time_add(cfs_time_current(), cfs_time_seconds(*ksocknal_tunables.ksnd_timeout));
    write_lock_bh(&ksocknal_data.ksnd_global_lock);
    LASSERT(route->ksnr_scheduled);
    LASSERT(!route->ksnr_connecting);
    route->ksnr_connecting = 1;
    for (;;)
    {
        wanted = ksocknal_route_mask() & ~route->ksnr_connected;
        if (peer->ksnp_closing || route->ksnr_deleted || wanted == 0)
        {
            retry_later = 0;
            break;
        }
        if (peer->ksnp_accepting > 0)
        {
            CDEBUG(D_NET, "peer %s(%d) already connecting to me, retry later.\n", libcfs_nid2str(peer->ksnp_id.nid), peer->ksnp_accepting);
            retry_later = 1;
        }
        if (retry_later)
        {
            break;
        }
        if ((wanted & (1 << SOCKLND_CONN_ANY)) != 0)
        {
            type = SOCKLND_CONN_ANY;
        }
        if ((wanted & (1 << SOCKLND_CONN_CONTROL)) != 0)
        {
            type = SOCKLND_CONN_CONTROL;
        }
        if ((wanted & (1 << SOCKLND_CONN_BULK_IN)) != 0)
        {
            type = SOCKLND_CONN_BULK_IN;
        }
        else
        {
            LASSERT((wanted & (1 << SOCKLND_CONN_BULK_OUT)) != 0);
            type = SOCKLND_CONN_BULK_OUT;
        }
        write_unlock_bh(&ksocknal_data.ksnd_global_lock);
        if (cfs_time_aftereq(cfs_time_current(), deadline))
        {
            rc = -ETIMEDOUT;
            lnet_connect_console_error(rc, peer->ksnp_id.nid, route->ksnr_ipaddr, route->ksnr_port);
            failed
        }
        rc = lnet_connect(&sock, peer->ksnp_id.nid, route->ksnr_myipaddr, route->ksnr_ipaddr, route->ksnr_port);
        if (rc != 0)
        {
            failed
        }
        rc = ksocknal_create_conn(peer->ksnp_ni, route, sock, type);
        if (rc < 0)
        {
            lnet_connect_console_error(rc, peer->ksnp_id.nid, route->ksnr_ipaddr, route->ksnr_port);
            failed
        }
        retry_later = (rc != 0);
        if (retry_later)
        {
            CDEBUG(D_NET, "peer %s: conn race, retry later.\n", libcfs_nid2str(peer->ksnp_id.nid));
        }
        write_lock_bh(&ksocknal_data.ksnd_global_lock);
    }
    route->ksnr_scheduled = 0;
    route->ksnr_connecting = 0;
    if (retry_later)
    {
        if (rc == EALREADY || (rc == 0 && peer->ksnp_accepting > 0))
        {
            route->ksnr_retry_interval = cfs_time_seconds(*ksocknal_tunables.ksnd_min_reconnectms) / 1000;
            route->ksnr_timeout = cfs_time_add(cfs_time_current(), route->ksnr_retry_interval);
        }
        ksocknal_launch_connection_locked(route);
    }
    write_unlock_bh(&ksocknal_data.ksnd_global_lock);
    return retry_later;
    failed write_lock_bh(&ksocknal_data.ksnd_global_lock);
    route->ksnr_scheduled = 0;
    route->ksnr_connecting = 0;
    route->ksnr_retry_interval *= 2;
    route->ksnr_retry_interval = MAX(route->ksnr_retry_interval, cfs_time_seconds(*ksocknal_tunables.ksnd_min_reconnectms) / 1000);
    route->ksnr_retry_interval = MIN(route->ksnr_retry_interval, cfs_time_seconds(*ksocknal_tunables.ksnd_max_reconnectms) / 1000);
    LASSERT(route->ksnr_retry_interval != 0);
    route->ksnr_timeout = cfs_time_add(cfs_time_current(), route->ksnr_retry_interval);
    if (!list_empty(&peer->ksnp_tx_queue) && peer->ksnp_accepting == 0 && ksocknal_find_connecting_route_locked(peer) == NULL)
    {
        ksock_conn_t *conn;
        if (!list_empty(&peer->ksnp_conns))
        {
            conn = list_entry(peer->ksnp_conns.next, ksock_conn_t, ksnc_list);
            LASSERT(conn->ksnc_proto == &ksocknal_protocol_v3x);
        }
        list_splice_init(&peer->ksnp_tx_queue, &zombies);
    }
    if (!route->ksnr_deleted)
    {
        list_del(&route->ksnr_list);
        list_add_tail(&route->ksnr_list, &peer->ksnp_routes);
    }
    write_unlock_bh(&ksocknal_data.ksnd_global_lock);
    ksocknal_peer_failed(peer);
    ksocknal_txlist_done(peer->ksnp_ni, &zombies, 1);
    return 0;
}