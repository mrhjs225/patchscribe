void lstcon_rpc_pinger(void *arg)
{
    stt_timer_t *ptimer = (stt_timer_t *)arg;
    lstcon_rpc_trans_t *trans;
    lstcon_rpc_t *crpc;
    srpc_msg_t *rep;
    srpc_debug_reqst_t *drq;
    lstcon_ndlink_t *ndl;
    lstcon_node_t *nd;
    time_t intv;
    int count = 0;
    int rc;
    mutex_lock(&console_session.ses_mutex);
    if (console_session.ses_shutdown || console_session.ses_expired)
    {
        mutex_unlock(&console_session.ses_mutex);
        return;
    }
    if (!console_session.ses_expired && cfs_time_current_sec() - console_session.ses_laststamp > (time_t)console_session.ses_timeout)
    {
        console_session.ses_expired = 1;
    }
    trans = console_session.ses_ping;
    LASSERT(trans != NULL);
    list_for_each_entry(, , )
    {
        nd = ndl->ndl_node;
        if (console_session.ses_expired)
        {
            if (nd->nd_state != LST_NODE_ACTIVE)
            {
                continue;
            }
            rc = lstcon_sesrpc_prep(nd, LST_TRANS_SESEND, trans->tas_features, &crpc);
            if (rc != 0)
            {
                CERROR("Out of memory\n");
                break;
            }
            lstcon_rpc_trans_addreq(trans, crpc);
            lstcon_rpc_post(crpc);
            continue;
        }
        crpc = &nd->nd_ping;
        if (crpc->crp_rpc != NULL)
        {
            LASSERT(crpc->crp_trans == trans);
            LASSERT(!list_empty(&crpc->crp_link));
            spin_lock(&crpc->crp_rpc->crpc_lock);
            LASSERT(crpc->crp_posted);
            if (!crpc->crp_finished)
            {
                spin_unlock(&crpc->crp_rpc->crpc_lock);
                continue;
            }
            spin_unlock(&crpc->crp_rpc->crpc_lock);
            lstcon_rpc_get_reply(crpc, &rep);
            list_del_init(&crpc->crp_link);
            lstcon_rpc_put(crpc);
        }
        if (nd->nd_state != LST_NODE_ACTIVE)
        {
            continue;
        }
        intv = cfs_duration_sec(cfs_time_sub(cfs_time_current(), nd->nd_stamp));
        if (intv < (time_t)nd->nd_timeout / 2)
        {
            continue;
        }
        rc = lstcon_rpc_init(nd, SRPC_SERVICE_DEBUG, trans->tas_features, 0, 0, 1, crpc);
        if (rc != 0)
        {
            CERROR("Out of memory\n");
            break;
        }
        drq = &crpc->crp_rpc->crpc_reqstmsg.msg_body.dbg_reqst;
        drq->dbg_sid = console_session.ses_id;
        drq->dbg_flags = 0;
        lstcon_rpc_trans_addreq(trans, crpc);
        lstcon_rpc_post(crpc);
        count++;
    }
    if (console_session.ses_expired)
    {
        mutex_unlock(&console_session.ses_mutex);
        return;
    }
    CDEBUG(D_NET, "Ping %d nodes in session\n", count);
    ptimer->stt_expires = (unsigned long)(cfs_time_current_sec() + LST_PING_INTERVAL);
    stt_add_timer(ptimer);
    mutex_unlock(&console_session.ses_mutex);
}