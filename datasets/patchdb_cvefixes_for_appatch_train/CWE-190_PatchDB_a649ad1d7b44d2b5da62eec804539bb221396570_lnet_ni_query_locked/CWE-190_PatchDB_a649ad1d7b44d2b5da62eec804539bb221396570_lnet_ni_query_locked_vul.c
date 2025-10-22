void lnet_ni_query_locked(lnet_ni_t *ni, lnet_peer_t *lp)
{
    cfs_time_t last_alive = 0;
    LASSERT(lnet_peer_aliveness_enabled(lp));
    LASSERT(ni->ni_lnd->lnd_query != NULL);
    lnet_net_unlock(lp->lp_cpt);
    (ni->ni_lnd->lnd_query)(ni, lp->lp_nid, &last_alive);
    lnet_net_lock(lp->lp_cpt);
    lp->lp_last_query = cfs_time_current();
    if (last_alive != 0)
    {
        lp->lp_last_alive = last_alive;
    }
}