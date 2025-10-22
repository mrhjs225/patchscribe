void kiblnd_pool_free_node(kib_pool_t *pool, struct list_head *node)
{
    LIST_HEAD(zombies);
    kib_poolset_t *ps = pool->po_owner;
    kib_pool_t *tmp;
    cfs_time_t now = cfs_time_current();
    spin_lock(&ps->ps_lock);
    if (ps->ps_node_fini != NULL)
    {
        ps->ps_node_fini(pool, node);
    }
    LASSERT(pool->po_allocated > 0);
    list_add(node, &pool->po_free_list);
    pool->po_allocated--;
    list_for_each_entry_safe(, , , )
    {
        if (ps->ps_pool_list.next == &pool->po_list)
        {
            continue;
        }
        if (kiblnd_pool_is_idle(pool, now))
        {
            list_move(&pool->po_list, &zombies);
        }
    }
    spin_unlock(&ps->ps_lock);
    if (!list_empty(&zombies))
    {
        kiblnd_destroy_pool_list(&zombies);
    }
}