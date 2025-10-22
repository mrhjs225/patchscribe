static int virtual_config_expand_wildcards(struct virtual_parse_context *ctx)
{
    struct mail_user *user = ctx->mbox->storage->storage.ns->user;
    ARRAY_TYPE()
    wildcard_boxes, neg_boxes;
    struct mailbox_list_iterate_context *iter;
    struct virtual_backend_box *const *wboxes;
    const char **patterns;
    const struct mailbox_info *info;
    unsigned int i, j, count;
    separate_wildcard_mailboxes(ctx->mbox, &wildcard_boxes, &neg_boxes);
    wboxes = array_get_modifiable(&wildcard_boxes, &count);
    patterns = t_new(const char *, count + 1);
    for (i = 0; i < count; i++)
    {
        patterns[i] = wboxes[i]->name;
    }
    iter = mailbox_list_iter_init_namespaces(user->namespaces, patterns, MAILBOX_LIST_ITER_VIRTUAL_NAMES | MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
    while ((info = mailbox_list_iter_next(iter)) != NULL)
    {
        if ((info->flags & MAILBOX_NOSELECT) != 0)
        {
            continue;
        }
        if (virtual_config_match(info, &wildcard_boxes, &i) && !virtual_config_match(info, &neg_boxes, &j))
        {
            virtual_config_copy_expanded(ctx, wboxes[i], info->name);
        }
    }
    for (i = 0; i < count; i++)
    {
        mail_search_args_unref(&wboxes[i]->search_args);
    }
    return mailbox_list_iter_deinit(&iter);
}