static ut64 Elf_(get_import_addr)(Elf_(r_bin_elf_obj_t) * bin, int sym)(Elf_(Rel) *rel = NULL, Elf_() plt_sym_addr, ut64 got_addr, got_offset, int i, j, k, tsize, len, (!bin->shdr || !bin->strtab) return -1;);
if ((got_offset = Elf_(r_bin_elf_get_section_offset)(bin, ".got")) == -1 && (got_offset = Elf_(r_bin_elf_get_section_offset)(bin, ".got.plt")) == -1)
{
    return -1;
}
if ((got_addr = Elf_(r_bin_elf_get_section_addr)(bin, ".got")) == -1 && (got_addr = Elf_(r_bin_elf_get_section_addr)(bin, ".got.plt")) == -1)
{
    return -1;
}
for (i = 0; i < bin->ehdr.e_shnum; i++)
{
    if (!strcmp(&bin->strtab[bin->shdr[i].sh_name], ".rel.plt"))
    {
        tsize = sizeof(Elf_(Rel));
    }
    if (!strcmp(&bin->strtab[bin->shdr[i].sh_name], ".rela.plt"))
    {
        tsize = sizeof(Elf_(Rela));
    }
    else
    {
        continue;
    }
    free(rel);
    if ((rel = (Elf_(Rel) *)malloc((int)(bin->shdr[i].sh_size / tsize) * sizeof(Elf_(Rel)))) == NULL)
    {
        perror("malloc (rel)");
        return -1;
    }
    for (j = k = 0; j < bin->shdr[i].sh_size; j += tsize, k++)
    {
        len = r_buf_fread_at(bin->b, bin->shdr[i].sh_offset + j, (ut8 *)&rel[k], bin->endian ? "2L" : "2l", bin->endian ? "2I" : "2i", 1);
        if (len == -1)
        {
            eprintf("Error: read (rel)\n");
            free(rel);
            return -1;
        }
    }
    for (j = k = 0; j < bin->shdr[i].sh_size; j += tsize, k++)
    {
        if (ELF_R_SYM(rel[k].r_info) == sym)
        {
            if (r_buf_read_at(bin->b, rel[k].r_offset - got_addr + got_offset, (ut8 *)&plt_sym_addr, sizeof(Elf_(Addr))) == -1)
            {
                eprintf("Error: read (got)\n");
                return UT64_MAX;
            }
            free(rel);
            return (ut64)(plt_sym_addr - 6);
        }
    }
    break;
}
free(rel);
return UT64_MAX;