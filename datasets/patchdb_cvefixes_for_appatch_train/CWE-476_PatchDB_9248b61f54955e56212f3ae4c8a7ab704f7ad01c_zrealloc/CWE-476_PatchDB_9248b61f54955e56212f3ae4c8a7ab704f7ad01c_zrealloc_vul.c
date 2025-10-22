void *zrealloc(int type, void *ptr, size_t size)
{
    void *memory;
    memory = realloc(ptr, size);
    if (memory == NULL)
    {
        zerror("realloc", type, size);
    }
    if (ptr == NULL)
    {
        alloc_inc(type);
    }
    return memory;
}