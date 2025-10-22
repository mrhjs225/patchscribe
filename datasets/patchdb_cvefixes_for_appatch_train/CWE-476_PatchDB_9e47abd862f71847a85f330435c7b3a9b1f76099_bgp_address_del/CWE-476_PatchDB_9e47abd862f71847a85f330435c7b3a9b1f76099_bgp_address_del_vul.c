static void bgp_address_del(struct prefix *p)
{
    struct bgp_addr tmp;
    struct bgp_addr *addr;
    tmp.addr = p->u.prefix4;
    addr = hash_lookup(bgp_address_hash, &tmp);
    addr->refcnt--;
    if (addr->refcnt == 0)
    {
        hash_release(bgp_address_hash, addr);
        XFREE(MTYPE_BGP_ADDR, addr);
    }
}