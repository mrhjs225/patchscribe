void ksocknal_check_peer_timeouts(int idx)
{
    struct list_head *peers = &ksocknal_data.ksnd_peers[idx];
    ksock_peer_t *peer;
    ksock_conn_t *conn;
    ksock_tx_t *tx;
    again read_lock(&ksocknal_data.ksnd_global_lock);
    list_for_each_entry(, , )
    {
        cfs_time_t deadline = 0;
        int resid = 0;
        int n = 0;
        if (ksocknal_send_keepalive_locked(peer) != 0)
        {
            read_unlock(&ksocknal_data.ksnd_global_lock);
            again
        }
        conn = ksocknal_find_timed_out_conn(peer);
        if (conn != NULL)
        {
            read_unlock(&ksocknal_data.ksnd_global_lock);
            ksocknal_close_conn_and_siblings(conn, -ETIMEDOUT);
            ksocknal_conn_decref(conn);
            again
        }
        if (!list_empty(&peer->ksnp_tx_queue))
        {
            ksock_tx_t *tx = list_entry(peer->ksnp_tx_queue.next, ksock_tx_t, tx_list);
            if (cfs_time_aftereq(cfs_time_current(), tx->tx_deadline))
            {
                ksocknal_peer_addref(peer);
                read_unlock(&ksocknal_data.ksnd_global_lock);
                ksocknal_flush_stale_txs(peer);
                ksocknal_peer_decref(peer);
                again
            }
        }
        if (list_empty(&peer->ksnp_zc_req_list))
        {
            continue;
        }
        spin_lock(&peer->ksnp_lock);
        list_for_each_entry(, , )
        {
            if (!cfs_time_aftereq(cfs_time_current(), tx->tx_deadline))
            {
                break;
            }
            if (tx->tx_conn->ksnc_closing)
            {
                continue;
            }
            n++;
        }
        if (n == 0)
        {
            spin_unlock(&peer->ksnp_lock);
            continue;
        }
        tx = list_entry(peer->ksnp_zc_req_list.next, ksock_tx_t, tx_zc_list);
        deadline = tx->tx_deadline;
        resid = tx->tx_resid;
        conn = tx->tx_conn;
        ksocknal_conn_addref(conn);
        spin_unlock(&peer->ksnp_lock);
        read_unlock(&ksocknal_data.ksnd_global_lock);
        CERROR("Total %d stale ZC_REQs for peer %s detected; the "
               "oldest(%p) timed out %ld secs ago, "
               "resid: %d, wmem: %d\n",
               n, libcfs_nid2str(peer->ksnp_id.nid), tx, cfs_duration_sec(cfs_time_current() - deadline), resid, conn->ksnc_sock->sk->sk_wmem_queued);
        ksocknal_close_conn_and_siblings(conn, -ETIMEDOUT);
        ksocknal_conn_decref(conn);
        again
    }
    read_unlock(&ksocknal_data.ksnd_global_lock);
}