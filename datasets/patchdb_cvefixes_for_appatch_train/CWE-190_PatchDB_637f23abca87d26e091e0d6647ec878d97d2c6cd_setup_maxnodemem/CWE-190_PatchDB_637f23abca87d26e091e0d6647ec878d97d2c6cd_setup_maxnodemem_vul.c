static int __init setup_maxnodemem(char *str)
{
    char *endp;
    unsigned long long maxnodemem;
    long node;
    node = str ? simple_strtoul(str, &endp, 0) : INT_MAX;
    if (node >= MAX_NUMNODES || *endp != ':')
    {
        return -EINVAL;
    }
    maxnodemem = memparse(endp + 1, NULL);
    maxnodemem_pfn[node] = (maxnodemem >> HPAGE_SHIFT) << (HPAGE_SHIFT - PAGE_SHIFT);
    pr_info("Forcing RAM used on node %ld to no more than %dMB\n", node, maxnodemem_pfn[node] >> (20 - PAGE_SHIFT));
    return 0;
}