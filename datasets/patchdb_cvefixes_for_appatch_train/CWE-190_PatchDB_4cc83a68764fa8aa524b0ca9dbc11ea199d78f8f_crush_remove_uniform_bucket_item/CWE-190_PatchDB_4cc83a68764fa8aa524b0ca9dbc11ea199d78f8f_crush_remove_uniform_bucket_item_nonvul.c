int crush_remove_uniform_bucket_item(struct crush_bucket_uniform *bucket, int item)
{
    unsigned i, j;
    int newsize;
    for (i = 0; i < bucket->h.size; i++)
    {
        if (bucket->h.items[i] == item)
        {
            break;
        }
    }
    if (i == bucket->h.size)
    {
        return -ENOENT;
    }
    for (j = i; j < bucket->h.size; j++)
    {
        bucket->h.items[j] = bucket->h.items[j + 1];
    }
    newsize = --bucket->h.size;
    bucket->h.weight -= bucket->item_weight;
    bucket->h.items = realloc(bucket->h.items, sizeof(__u32) * newsize);
    bucket->h.perm = realloc(bucket->h.perm, sizeof(__u32) * newsize);
    return 0;
}