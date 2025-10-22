int crush_remove_list_bucket_item(struct crush_bucket_list *bucket, int item)
{
    int i, j;
    int newsize;
    int weight;
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
    weight = bucket->item_weights[i];
    for (j = i; j < bucket->h.size; j++)
    {
        bucket->h.items[j] = bucket->h.items[j + 1];
        bucket->item_weights[j] = bucket->item_weights[j + 1];
        bucket->sum_weights[j] = bucket->sum_weights[j + 1] - weight;
    }
    bucket->h.weight -= weight;
    newsize = --bucket->h.size;
    bucket->h.items = realloc(bucket->h.items, sizeof(__u32) * newsize);
    bucket->h.perm = realloc(bucket->h.perm, sizeof(__u32) * newsize);
    bucket->item_weights = realloc(bucket->item_weights, sizeof(__u32) * newsize);
    bucket->sum_weights = realloc(bucket->sum_weights, sizeof(__u32) * newsize);
    return 0;
}