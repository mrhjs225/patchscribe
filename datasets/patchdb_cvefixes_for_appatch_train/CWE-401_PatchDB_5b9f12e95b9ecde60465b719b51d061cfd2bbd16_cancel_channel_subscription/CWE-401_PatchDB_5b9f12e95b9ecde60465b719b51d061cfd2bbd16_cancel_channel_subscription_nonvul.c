static int cancel_channel_subscription(struct nerd_channel *chan, int sd)
{
    objectlist *list, *next, *prev = NULL;
    int cancelled = 0;
    if (!chan)
    {
        return -1;
    }
    for (list = chan->subscriptions; list; list = next)
    {
        struct subscription *subscr = (subscription *)list->object_ptr;
        next = list->next;
        if (subscr->sd == sd)
        {
            cancelled++;
            free(list);
            free(subscr);
            if (prev)
            {
                prev->next = next;
            }
            else
            {
                chan->subscriptions = next;
            }
            continue;
        }
        prev = list;
    }
    if (cancelled)
    {
        logit(NSLOG_INFO_MESSAGE, TRUE, "nerd: Cancelled %d subscription%s to channel '%s' for %d\n", cancelled, cancelled == 1 ? "" : "s", chan->name, sd);
    }
    if (chan->subscriptions == NULL)
    {
        nerd_deregister_channel_callbacks(chan);
    }
    return 0;
}