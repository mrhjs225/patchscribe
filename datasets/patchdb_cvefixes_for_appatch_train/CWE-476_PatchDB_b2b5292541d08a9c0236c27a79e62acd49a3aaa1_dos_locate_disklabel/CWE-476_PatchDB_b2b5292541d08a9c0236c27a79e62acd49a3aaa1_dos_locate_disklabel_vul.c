static int dos_locate_disklabel(struct fdisk_context *cxt, int n, const char **name, uint64_t *offset, size_t *size)
{
    assert(cxt);
    *name = NULL;
    *offset = 0;
    *size = 0;
    switch (n)
    {
    case 0:
        *name = "MBR";
        *offset = 0;
        *size = 512;
        break;
    default:
        if ((size_t)n - 1 + 4 < cxt->label->nparts_max)
        {
            struct pte *pe = self_pte(cxt, n - 1 + 4);
            assert(pe->private_sectorbuffer);
            *name = "EBR";
            *offset = (uint64_t)pe->offset * cxt->sector_size;
            *size = 512;
        }
        else
        {
            return 1;
        }
        break;
    }
    return 0;
}