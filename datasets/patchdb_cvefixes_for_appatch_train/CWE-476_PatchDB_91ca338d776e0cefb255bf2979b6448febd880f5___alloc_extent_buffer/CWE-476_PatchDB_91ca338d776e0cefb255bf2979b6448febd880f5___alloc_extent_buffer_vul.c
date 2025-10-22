static struct extent_buffer *__alloc_extent_buffer(struct extent_io_tree *tree, u64 start, unsigned long len, gfp_t mask)
{
    struct extent_buffer *eb = NULL;
    unsigned long flags;
    eb = kmem_cache_zalloc(extent_buffer_cache, mask);
    eb->start = start;
    eb->len = len;
    spin_lock_init(&eb->lock);
    init_waitqueue_head(&eb->lock_wq);
    INIT_RCU_HEAD(&eb->rcu_head);
    spin_lock_irqsave(&leak_lock, flags);
    list_add(&eb->leak_list, &buffers);
    spin_unlock_irqrestore(&leak_lock, flags);
    atomic_set(&eb->refs, 1);
    return eb;
}