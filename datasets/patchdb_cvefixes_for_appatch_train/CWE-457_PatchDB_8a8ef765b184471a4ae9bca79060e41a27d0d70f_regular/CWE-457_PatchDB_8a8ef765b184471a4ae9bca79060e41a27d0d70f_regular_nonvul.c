int regular(const char *file, int fd, Elf *elf, uint_t flags, const char *wname, int wfd, uchar_t osabi)
{
    {CACHE_NEEDED, CACHE_OK, CACHE_FAIL}, cache_state = CACHE_NEEDED Elf_Scn * scn;
    Ehdr *ehdr;
    size_t ndx, shstrndx, shnum, phnum;
    Shdr *shdr;
    Cache *cache;
    VERSYM_STATE versym = {0};
    int ret = 0;
    int addr_align;
    if ((ehdr = elf_getehdr(elf)) == NULL)
    {
        failure(file, MSG_ORIG(MSG_ELF_GETEHDR));
        return (ret);
    }
    if (elf_getshdrnum(elf, &shnum) == -1)
    {
        failure(file, MSG_ORIG(MSG_ELF_GETSHDRNUM));
        return (ret);
    }
    if (elf_getshdrstrndx(elf, &shstrndx) == -1)
    {
        failure(file, MSG_ORIG(MSG_ELF_GETSHDRSTRNDX));
        return (ret);
    }
    if (elf_getphdrnum(elf, &phnum) == -1)
    {
        failure(file, MSG_ORIG(MSG_ELF_GETPHDRNUM));
        return (ret);
    }
    if ((phnum == 0) && (flags & FLG_CTL_FAKESHDR))
    {
        (void)fprintf(stderr, MSG_INTL(MSG_ERR_PNEEDSPH), file);
        return (ret);
    }
    if ((scn = elf_getscn(elf, 0)) != NULL)
    {
        if ((shdr = elf_getshdr(scn)) == NULL)
        {
            failure(file, MSG_ORIG(MSG_ELF_GETSHDR));
            (void)fprintf(stderr, MSG_INTL(MSG_ELF_ERR_SCN), 0);
            return (ret);
        }
    }
    else
    {
        shdr = NULL;
    }
    if (flags & FLG_SHOW_EHDR)
    {
        Elf_ehdr(0, ehdr, shdr);
    }
    if (ehdr->e_machine == EM_AMD64)
    {
        addr_align = sizeof(Word);
    }
    else
    {
        addr_align = sizeof(Addr);
    }
    if (ehdr->e_phoff & (addr_align - 1))
    {
        (void)fprintf(stderr, MSG_INTL(MSG_ERR_BADPHDRALIGN), file);
    }
    if (ehdr->e_shoff & (addr_align - 1))
    {
        (void)fprintf(stderr, MSG_INTL(MSG_ERR_BADSHDRALIGN), file);
    }
    if (flags & FLG_CTL_OSABI)
    {
        if (osabi == ELFOSABI_NONE)
        {
            osabi = ELFOSABI_UNKNOWN4;
        }
    }
    else
    {
        osabi = ehdr->e_ident[EI_OSABI];
        if (osabi == ELFOSABI_NONE)
        {
            if (create_cache(file, fd, elf, ehdr, &cache, shstrndx, &shnum, &flags) == 0)
            {
                cache_state = CACHE_FAIL;
            }
            else
            {
                cache_state = CACHE_OK;
                if (has_linux_abi_note(cache, shnum, file))
                {
                    Conv_inv_buf_t ibuf1, ibuf2;
                    (void)fprintf(stderr, MSG_INTL(MSG_INFO_LINUXOSABI), file, conv_ehdr_osabi(osabi, 0, &ibuf1), conv_ehdr_osabi(ELFOSABI_LINUX, 0, &ibuf2));
                    osabi = ELFOSABI_LINUX;
                }
            }
        }
        if (osabi == ELFOSABI_NONE)
        {
            osabi = ELFOSABI_SOLARIS;
        }
    }
    if ((flags & FLG_SHOW_PHDR) && (phnum != 0))
    {
        Phdr *phdr;
        if ((phdr = elf_getphdr(elf)) == NULL)
        {
            failure(file, MSG_ORIG(MSG_ELF_GETPHDR));
            return (ret);
        }
        for (ndx = 0; ndx < phnum; phdr++, ndx++)
        {
            if (!match(MATCH_F_PHDR | MATCH_F_NDX | MATCH_F_TYPE, NULL, ndx, phdr->p_type))
            {
                continue;
            }
            dbg_print(0, MSG_ORIG(MSG_STR_EMPTY));
            dbg_print(0, MSG_INTL(MSG_ELF_PHDR), EC_WORD(ndx));
            Elf_phdr(0, osabi, ehdr->e_machine, phdr);
        }
    }
    if (((flags & (FLG_MASK_SHOW | FLG_MASK_CALC)) != 0) && ((flags & (FLG_MASK_SHOW_SHDR | FLG_MASK_CALC_SHDR)) == 0))
    {
        return (ret);
    }
    switch (cache_state)
    {
    case CACHE_NEEDED:
        if (create_cache(file, fd, elf, ehdr, &cache, shstrndx, &shnum, &flags) == 0)
        {
            return (ret);
        }
        break;
    case CACHE_FAIL:
        return (ret);
    }
    if (shnum <= 1)
    {
        done
    }
    if (wfd)
    {
        for (ndx = 1; ndx < shnum; ndx++)
        {
            Cache *_cache = &cache[ndx];
            if (match(MATCH_F_STRICT | MATCH_F_ALL, _cache->c_name, ndx, _cache->c_shdr->sh_type) && _cache->c_data && _cache->c_data->d_buf)
            {
                if (write(wfd, _cache->c_data->d_buf, _cache->c_data->d_size) != _cache->c_data->d_size)
                {
                    int err = errno;
                    (void)fprintf(stderr, MSG_INTL(MSG_ERR_WRITE), wname, strerror(err));
                    ret = 1;
                    done
                }
            }
        }
    }
    if ((wfd == 0) && (flags & FLG_CTL_MATCH) && ((flags & (FLG_MASK_SHOW | FLG_MASK_CALC)) == 0))
    {
        for (ndx = 1; ndx < shnum; ndx++)
        {
            Cache *_cache = &cache[ndx];
            if (!match(MATCH_F_STRICT | MATCH_F_ALL, _cache->c_name, ndx, _cache->c_shdr->sh_type))
            {
                continue;
            }
            switch (_cache->c_shdr->sh_type)
            {
            case SHT_PROGBITS:
                if (strcmp(_cache->c_name, MSG_ORIG(MSG_ELF_INTERP)) == 0)
                {
                    flags |= FLG_SHOW_INTERP;
                    break;
                }
                if (strcmp(_cache->c_name, MSG_ORIG(MSG_ELF_GOT)) == 0)
                {
                    flags |= FLG_SHOW_GOT;
                    break;
                }
                if ((strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_FRM), MSG_SCN_FRM_SIZE) == 0) || (strncmp(_cache->c_name, MSG_ORIG(MSG_SCN_EXRANGE), MSG_SCN_EXRANGE_SIZE) == 0))
                {
                    flags |= FLG_SHOW_UNWIND;
                    break;
                }
                break;
            case SHT_SYMTAB:
            case SHT_DYNSYM:
            case SHT_SUNW_LDYNSYM:
            case SHT_SUNW_versym:
            case SHT_SYMTAB_SHNDX:
                flags |= FLG_SHOW_SYMBOLS;
                break;
            case SHT_RELA:
            case SHT_REL:
                flags |= FLG_SHOW_RELOC;
                break;
            case SHT_HASH:
                flags |= FLG_SHOW_HASH;
                break;
            case SHT_DYNAMIC:
                flags |= FLG_SHOW_DYNAMIC;
                break;
            case SHT_NOTE:
                flags |= FLG_SHOW_NOTE;
                break;
            case SHT_GROUP:
                flags |= FLG_SHOW_GROUP;
                break;
            case SHT_SUNW_symsort:
            case SHT_SUNW_tlssort:
                flags |= FLG_SHOW_SORT;
                break;
            case SHT_SUNW_cap:
                flags |= FLG_SHOW_CAP;
                break;
            case SHT_SUNW_move:
                flags |= FLG_SHOW_MOVE;
                break;
            case SHT_SUNW_syminfo:
                flags |= FLG_SHOW_SYMINFO;
                break;
            case SHT_SUNW_verdef:
            case SHT_SUNW_verneed:
                flags |= FLG_SHOW_VERSIONS;
                break;
            case SHT_AMD64_UNWIND:
                flags |= FLG_SHOW_UNWIND;
                break;
            }
        }
    }
    if (flags & FLG_SHOW_SHDR)
    {
        sections(file, cache, shnum, ehdr, osabi);
    }
    if (flags & FLG_SHOW_INTERP)
    {
        interp(file, cache, shnum, phnum, elf);
    }
    if ((osabi == ELFOSABI_SOLARIS) || (osabi == ELFOSABI_LINUX))
    {
        versions(cache, shnum, file, flags, &versym);
    }
    if (flags & FLG_SHOW_SYMBOLS)
    {
        symbols(cache, shnum, ehdr, osabi, &versym, file, flags);
    }
    if ((flags & FLG_SHOW_SORT) && (osabi == ELFOSABI_SOLARIS))
    {
        sunw_sort(cache, shnum, ehdr, osabi, &versym, file, flags);
    }
    if (flags & FLG_SHOW_HASH)
    {
        hash(cache, shnum, file, flags);
    }
    if (flags & FLG_SHOW_GOT)
    {
        got(cache, shnum, ehdr, file);
    }
    if (flags & FLG_SHOW_GROUP)
    {
        group(cache, shnum, file, flags);
    }
    if (flags & FLG_SHOW_SYMINFO)
    {
        syminfo(cache, shnum, ehdr, osabi, file);
    }
    if (flags & FLG_SHOW_RELOC)
    {
        reloc(cache, shnum, ehdr, file);
    }
    if (flags & FLG_SHOW_DYNAMIC)
    {
        dynamic(cache, shnum, ehdr, osabi, file);
    }
    if (flags & FLG_SHOW_NOTE)
    {
        Word note_cnt;
        size_t note_shnum;
        Cache *note_cache;
        note_cnt = note(cache, shnum, ehdr, file);
        if ((note_cnt == 0) && (ehdr->e_type == ET_CORE) && !(flags & FLG_CTL_FAKESHDR) && (fake_shdr_cache(file, fd, elf, ehdr, &note_cache, &note_shnum) != 0))
        {
            (void)note(note_cache, note_shnum, ehdr, file);
            fake_shdr_cache_free(note_cache, note_shnum);
        }
    }
    if ((flags & FLG_SHOW_MOVE) && (osabi == ELFOSABI_SOLARIS))
    {
        move(cache, shnum, file, flags);
    }
    if (flags & FLG_CALC_CHECKSUM)
    {
        checksum(elf);
    }
    if ((flags & FLG_SHOW_CAP) && (osabi == ELFOSABI_SOLARIS))
    {
        cap(file, cache, shnum, phnum, ehdr, osabi, elf, flags);
    }
    if ((flags & FLG_SHOW_UNWIND) && ((osabi == ELFOSABI_SOLARIS) || (osabi == ELFOSABI_LINUX)))
    {
        unwind(cache, shnum, phnum, ehdr, osabi, file, elf, flags);
    }
    done if (flags & FLG_CTL_FAKESHDR) { fake_shdr_cache_free(cache, shnum); }
    else { free(cache); }
    return (ret);
}