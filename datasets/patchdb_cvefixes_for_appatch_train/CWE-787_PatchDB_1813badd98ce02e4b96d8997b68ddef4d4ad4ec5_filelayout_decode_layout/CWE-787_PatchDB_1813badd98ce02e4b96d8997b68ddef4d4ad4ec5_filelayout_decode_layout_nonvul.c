static int filelayout_decode_layout(struct pnfs_layout_hdr *flo, struct nfs4_filelayout_segment *fl, struct nfs4_layoutget_res *lgr, struct nfs4_deviceid *id, gfp_t gfp_flags)
{
    struct xdr_stream stream;
    struct xdr_buf buf;
    struct page *scratch;
    __be32 *p;
    uint32_t nfl_util;
    int i;
    dprintk("%s: set_layout_map Begin\n", __func__);
    scratch = alloc_page(gfp_flags);
    if (!scratch)
    {
        return -ENOMEM;
    }
    xdr_init_decode_pages(&stream, &buf, lgr->layoutp->pages, lgr->layoutp->len);
    xdr_set_scratch_buffer(&stream, page_address(scratch), PAGE_SIZE);
    p = xdr_inline_decode(&stream, NFS4_DEVICEID4_SIZE + 20);
    if (unlikely(!p))
    {
        out_err
    }
    memcpy(id, p, sizeof(*id));
    p += XDR_QUADLEN(NFS4_DEVICEID4_SIZE);
    nfs4_print_deviceid(id);
    nfl_util = be32_to_cpup(p++);
    if (nfl_util & NFL4_UFLG_COMMIT_THRU_MDS)
    {
        fl->commit_through_mds = 1;
    }
    if (nfl_util & NFL4_UFLG_DENSE)
    {
        fl->stripe_type = STRIPE_DENSE;
    }
    else
    {
        fl->stripe_type = STRIPE_SPARSE;
    }
    fl->stripe_unit = nfl_util & ~NFL4_UFLG_MASK;
    fl->first_stripe_index = be32_to_cpup(p++);
    p = xdr_decode_hyper(p, &fl->pattern_offset);
    fl->num_fh = be32_to_cpup(p++);
    dprintk("%s: nfl_util 0x%X num_fh %u fsi %u po %llu\n", __func__, nfl_util, fl->num_fh, fl->first_stripe_index, fl->pattern_offset);
    if (fl->num_fh > max(NFS4_PNFS_MAX_STRIPE_CNT, NFS4_PNFS_MAX_MULTI_CNT))
    {
        out_err
    }
    if (fl->num_fh > 0)
    {
        fl->fh_array = kcalloc(fl->num_fh, sizeof(fl->fh_array[0]), gfp_flags);
        if (!fl->fh_array)
        {
            out_err
        }
    }
    for (i = 0; i < fl->num_fh; i++)
    {
        fl->fh_array[i] = kmalloc(sizeof(nfs_fh), gfp_flags);
        if (!fl->fh_array[i])
        {
            out_err_free
        }
        p = xdr_inline_decode(&stream, 4);
        if (unlikely(!p))
        {
            out_err_free
        }
        fl->fh_array[i]->size = be32_to_cpup(p++);
        if (sizeof(nfs_fh) < fl->fh_array[i]->size)
        {
            printk(KERN_ERR "NFS: Too big fh %d received %d\n", i, fl->fh_array[i]->size);
            out_err_free
        }
        p = xdr_inline_decode(&stream, fl->fh_array[i]->size);
        if (unlikely(!p))
        {
            out_err_free
        }
        memcpy(fl->fh_array[i]->data, p, fl->fh_array[i]->size);
        dprintk("DEBUG: %s: fh len %d\n", __func__, fl->fh_array[i]->size);
    }
    __free_page(scratch);
    return 0;
    out_err_free filelayout_free_fh_array(fl);
    out_err __free_page(scratch);
    return -EIO;
}