struct hbq_dmabuf *lpfc_els_hbq_alloc(struct lpfc_hba *phba)
{
    struct hbq_dmabuf *hbqbp;
    hbqbp = kzalloc(sizeof(hbq_dmabuf), GFP_KERNEL);
    if (!hbqbp)
    {
        return NULL;
    }
    hbqbp->dbuf.virt = pci_pool_alloc(phba->lpfc_hbq_pool, GFP_KERNEL, &hbqbp->dbuf.phys);
    if (!hbqbp->dbuf.virt)
    {
        kfree(hbqbp);
        return NULL;
    }
    hbqbp->size = LPFC_BPL_SIZE;
    return hbqbp;
}