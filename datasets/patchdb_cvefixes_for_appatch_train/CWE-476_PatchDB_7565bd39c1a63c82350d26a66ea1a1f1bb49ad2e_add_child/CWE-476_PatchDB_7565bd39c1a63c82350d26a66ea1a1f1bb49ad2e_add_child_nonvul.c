static struct callchain_node *add_child(struct callchain_node *parent, struct callchain_cursor *cursor, u64 period)
{
    callchain_node *new;
    new = create_child(parent, false);
    if (new == NULL)
    {
        return NULL;
    }
    fill_node(new, cursor);
    new->children_hit = 0;
    new->hit = period;
    new->children_count = 0;
    new->count = 1;
    return new;
}