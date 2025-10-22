static struct device_node *__of_get_next_child(const struct device_node *node, struct device_node *prev)
{
    struct device_node *next;
    if (!node)
    {
        return NULL;
    }
    next = prev ? prev->sibling : node->child;
    for (; next; next = next->sibling)
    {
        if (of_node_get(next))
        {
            break;
        }
    }
    of_node_put(prev);
    return next;
}