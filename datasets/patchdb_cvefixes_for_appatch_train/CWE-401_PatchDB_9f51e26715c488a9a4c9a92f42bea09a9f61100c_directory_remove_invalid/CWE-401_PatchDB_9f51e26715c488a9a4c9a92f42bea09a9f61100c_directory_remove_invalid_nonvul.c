static void directory_remove_invalid(void)
{
    int changed = 0;
    routerlist_t *rl = router_get_routerlist();
    smartlist_t *nodes = smartlist_create();
    smartlist_add_all(nodes, nodelist_get_list());
    SMARTLIST_FOREACH_BEGIN(, , )
    {
        const char *msg;
        routerinfo_t *ent = node->ri;
        uint32_t r;
        if (!ent)
        {
            continue;
        }
        r = dirserv_router_get_status(ent, &msg);
        if (r & FP_REJECT)
        {
            log_info(LD_DIRSERV, "Router '%s' is now rejected: %s", ent->nickname, msg ? msg : "");
            routerlist_remove(rl, ent, 0, time(NULL));
            changed = 1;
            continue;
        }
        if (bool_neq((r & FP_NAMED), ent->auth_says_is_named))
        {
            log_info(LD_DIRSERV, "Router '%s' is now %snamed.", ent->nickname, (r & FP_NAMED) ? "" : "un");
            ent->is_named = (r & FP_NAMED) ? 1 : 0;
            changed = 1;
        }
        if (bool_neq((r & FP_UNNAMED), ent->auth_says_is_unnamed))
        {
            log_info(LD_DIRSERV, "Router '%s' is now %snamed. (FP_UNNAMED)", ent->nickname, (r & FP_NAMED) ? "" : "un");
            ent->is_named = (r & FP_NUNAMED) ? 0 : 1;
            changed = 1;
        }
        if (bool_neq((r & FP_INVALID), !node->is_valid))
        {
            log_info(LD_DIRSERV, "Router '%s' is now %svalid.", ent->nickname, (r & FP_INVALID) ? "in" : "");
            node->is_valid = (r & FP_INVALID) ? 0 : 1;
            changed = 1;
        }
        if (bool_neq((r & FP_BADDIR), node->is_bad_directory))
        {
            log_info(LD_DIRSERV, "Router '%s' is now a %s directory", ent->nickname, (r & FP_BADDIR) ? "bad" : "good");
            node->is_bad_directory = (r & FP_BADDIR) ? 1 : 0;
            changed = 1;
        }
        if (bool_neq((r & FP_BADEXIT), node->is_bad_exit))
        {
            log_info(LD_DIRSERV, "Router '%s' is now a %s exit", ent->nickname, (r & FP_BADEXIT) ? "bad" : "good");
            node->is_bad_exit = (r & FP_BADEXIT) ? 1 : 0;
            changed = 1;
        }
    }
    SMARTLIST_FOREACH_END(node);
    if (changed)
    {
        directory_set_dirty();
    }
    routerlist_assert_ok(rl);
    smartlist_free(nodes);
}