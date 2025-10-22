int lstcon_rpc_trans_interpreter(lstcon_rpc_trans_t *trans, struct list_head *head_up, lstcon_rpc_readent_func_t readent)
{
    struct list_head tmp;
    struct list_head *next;
    lstcon_rpc_ent_t *ent;
    srpc_generic_reply_t *rep;
    lstcon_rpc_t *crpc;
    srpc_msg_t *msg;
    lstcon_node_t *nd;
    cfs_duration_t dur;
    struct timeval tv;
    int error;
    LASSERT(head_up != NULL);
    next = head_up;
    list_for_each_entry(, , )
    {
        if (copy_from_user(&tmp, next, sizeof(list_head)))
        {
            return -EFAULT;
        }
        if (tmp.next == head_up)
        {
            return 0;
        }
        next = tmp.next;
        ent = list_entry(next, lstcon_rpc_ent_t, rpe_link);
        LASSERT(crpc->crp_stamp != 0);
        error = lstcon_rpc_get_reply(crpc, &msg);
        nd = crpc->crp_node;
        dur = (cfs_duration_t)cfs_time_sub(crpc->crp_stamp, (cfs_time_t)console_session.ses_id.ses_stamp);
        cfs_duration_usec(dur, &tv);
        if (copy_to_user(&ent->rpe_peer, &nd->nd_id, sizeof(lnet_process_id_t)) || copy_to_user(&ent->rpe_stamp, &tv, sizeof(tv)) || copy_to_user(&ent->rpe_state, &nd->nd_state, sizeof(nd->nd_state)) || copy_to_user(&ent->rpe_rpc_errno, &error, sizeof(error)))
        {
            return -EFAULT;
        }
        if (error != 0)
        {
            continue;
        }
        rep = (srpc_generic_reply_t *)&msg->msg_body.reply;
        if (copy_to_user(&ent->rpe_sid, &rep->sid, sizeof(lst_sid_t)) || copy_to_user(&ent->rpe_fwk_errno, &rep->status, sizeof(rep->status)))
        {
            return -EFAULT;
        }
        if (readent == NULL)
        {
            continue;
        }
        error = readent(trans->tas_opc, msg, ent);
        if (error != 0)
        {
            return error;
        }
    }
    return 0;
}