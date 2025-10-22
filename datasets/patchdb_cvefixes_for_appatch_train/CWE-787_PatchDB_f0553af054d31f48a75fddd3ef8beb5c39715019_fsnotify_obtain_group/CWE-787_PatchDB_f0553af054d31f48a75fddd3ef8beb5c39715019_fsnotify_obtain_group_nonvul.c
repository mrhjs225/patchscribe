struct fsnotify_group *fsnotify_obtain_group(unsigned int group_num, __u32 mask, const struct fsnotify_ops *ops)
{
    struct fsnotify_group *group, *tgroup;
    group = kzalloc(sizeof(fsnotify_group), GFP_KERNEL);
    if (!group)
    {
        return ERR_PTR(-ENOMEM);
    }
    atomic_set(&group->refcnt, 1);
    group->on_group_list = 0;
    group->group_num = group_num;
    group->mask = mask;
    mutex_init(&group->notification_mutex);
    INIT_LIST_HEAD(&group->notification_list);
    init_waitqueue_head(&group->notification_waitq);
    group->q_len = 0;
    group->max_events = UINT_MAX;
    spin_lock_init(&group->mark_lock);
    atomic_set(&group->num_marks, 0);
    INIT_LIST_HEAD(&group->mark_entries);
    group->ops = ops;
    mutex_lock(&fsnotify_grp_mutex);
    tgroup = fsnotify_find_group(group_num, mask, ops);
    if (tgroup)
    {
        mutex_unlock(&fsnotify_grp_mutex);
        fsnotify_put_group(group);
        return tgroup;
    }
    list_add_rcu(&group->group_list, &fsnotify_groups);
    group->on_group_list = 1;
    atomic_inc(&group->num_marks);
    mutex_unlock(&fsnotify_grp_mutex);
    if (mask)
    {
        fsnotify_recalc_global_mask();
    }
    return group;
}