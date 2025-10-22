int lustre_check_remote_perm(struct inode *inode, int mask)
{
    struct ll_inode_info *lli = ll_i2info(inode);
    struct ll_sb_info *sbi = ll_i2sbi(inode);
    struct ptlrpc_request *req = NULL;
    struct mdt_remote_perm *perm;
    struct obd_capa *oc;
    unsigned long save;
    int i = 0, rc;
    {
        save = lli->lli_rmtperm_time;
        rc = do_check_remote_perm(lli, mask);
        if (!rc || (rc != -ENOENT && i))
        {
            break;
        }
        might_sleep();
        mutex_lock(&lli->lli_rmtperm_mutex);
        if (save != lli->lli_rmtperm_time)
        {
            rc = do_check_remote_perm(lli, mask);
            if (!rc || (rc != -ENOENT && i))
            {
                mutex_unlock(&lli->lli_rmtperm_mutex);
                break;
            }
        }
        if (i++ > 5)
        {
            CERROR("check remote perm falls in dead loop!\n");
            LBUG();
        }
        oc = ll_mdscapa_get(inode);
        rc = md_get_remote_perm(sbi->ll_md_exp, ll_inode2fid(inode), oc, ll_i2suppgid(inode), &req);
        capa_put(oc);
        if (rc)
        {
            mutex_unlock(&lli->lli_rmtperm_mutex);
            break;
        }
        perm = req_capsule_server_swab_get(&req->rq_pill, &RMF_ACL, lustre_swab_mdt_remote_perm);
        if (unlikely(perm == NULL))
        {
            mutex_unlock(&lli->lli_rmtperm_mutex);
            rc = -EPROTO;
            break;
        }
        rc = ll_update_remote_perm(inode, perm);
        mutex_unlock(&lli->lli_rmtperm_mutex);
        if (rc == -ENOMEM)
        {
            break;
        }
        ptlrpc_req_finished(req);
        req = NULL;
    }
    1;
    ptlrpc_req_finished(req);
    return rc;
}