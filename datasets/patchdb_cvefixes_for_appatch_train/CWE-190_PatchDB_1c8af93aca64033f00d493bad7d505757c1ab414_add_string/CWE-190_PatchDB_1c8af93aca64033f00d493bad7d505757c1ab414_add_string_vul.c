static int add_string(struct udev_rules *rules, const char *str)
{
    struct trie_node *child;
    unsigned short child_off;
    unsigned short node_off;
    unsigned char key;
    size_t len;
    int depth;
    unsigned int off;
    len = strlen(str);
    if (len == 0)
    {
        return 0;
    }
    if (strchr(str, ' ') != NULL)
    {
        return add_new_string(rules, str, len + 1);
    }
    key = str[len - 1];
    node_off = rules->trie_root[key];
    depth = 0;
    if (node_off != 0)
    {
        while (1)
        {
            struct trie_node *node = &rules->trie[node_off];
            unsigned char child_slot;
            depth++;
            off = node->value_off + node->value_len - len;
            if (depth == len || (node->value_len >= len && memcmp(&rules->buf[off], str, len) == 0))
            {
                return off;
            }
            key = str[len - 1 - depth];
            child_slot = trie_child_slot(node, key);
            if (child_slot == node->child_cur)
            {
                break;
            }
            node_off = node->child[child_slot];
        }
    }
    off = add_new_string(rules, str, len + 1);
    if (rules->trie_cur >= rules->trie_max)
    {
        struct trie_node *trie;
        unsigned short add;
        add = rules->trie_max;
        if (add < 8)
        {
            add = 8;
        }
        trie = realloc(rules->trie, (rules->trie_max + add) * sizeof(trie_node));
        if (trie == NULL)
        {
            return -1;
        }
        dbg(rules->udev, "extend string index nodes from %u to %u\n", rules->trie_max, rules->trie_max + add);
        rules->trie = trie;
        rules->trie_max += add;
    }
    child_off = rules->trie_cur;
    if (depth == 0)
    {
        rules->trie_root[key] = child_off;
    }
    else
    {
        struct trie_node *parent = &rules->trie[node_off];
        unsigned char child_slot = parent->child_cur;
        if (child_slot == TRIE_CHILD_MAX)
        {
            return off;
        }
        parent->child[child_slot] = child_off;
        parent->child_key[child_slot] = key;
        parent->child_cur = child_slot + 1;
    }
    rules->trie_cur++;
    child = &rules->trie[child_off];
    memset(child, 0x00, sizeof(trie_node));
    child->value_off = off;
    child->value_len = len;
    return off;
}