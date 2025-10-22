struct hbq_dmabuf *lpfc_sli4_rb_alloc(struct lpfc_hba *phba)
{
    struct hbq_dmabuf *dma_buf;
    dma_buf = kmalloc(sizeof(hbq_dmabuf), GFP_KERNEL);
    if (!dma_buf)
    {
        return NULL;
    }
    dma_buf->hbuf.virt = pci_pool_alloc(phba->lpfc_hrb_pool, GFP_KERNEL, &dma_buf->hbuf.phys);
    if (!dma_buf->hbuf.virt)
    {
        kfree(dma_buf);
        return NULL;
    }
    dma_buf->dbuf.virt = pci_pool_alloc(phba->lpfc_drb_pool, GFP_KERNEL, &dma_buf->dbuf.phys);
    if (!dma_buf->dbuf.virt)
    {
        pci_pool_free(phba->lpfc_hrb_pool, dma_buf->hbuf.virt, dma_buf->hbuf.phys);
        kfree(dma_buf);
        return NULL;
    }
    dma_buf->size = LPFC_BPL_SIZE;
    return dma_buf;
}