static int edit_dwarf2_line(DSO *dso, uint32_t off, char *comp_dir, int phase)
{
    unsigned char *ptr = debug_sections[DEBUG_LINE].data, *dir;
    unsigned char **dirt;
    unsigned char *endsec = ptr + debug_sections[DEBUG_LINE].size;
    unsigned char *endcu, *endprol;
    unsigned char opcode_base;
    uint32_t value, dirt_cnt;
    size_t comp_dir_len = strlen(comp_dir);
    size_t abs_file_cnt = 0, abs_dir_cnt = 0;
    if (phase != 0)
    {
        return 0;
    }
    if (ptr == NULL)
    {
        return 0;
    }
    ptr += off;
    endcu = ptr + 4;
    endcu += read_32(ptr);
    if (endcu == ptr + 0xffffffff)
    {
        error(0, 0, "%s: 64-bit DWARF not supported", dso->filename);
        return 1;
    }
    if (endcu > endsec)
    {
        error(0, 0, "%s: .debug_line CU does not fit into section", dso->filename);
        return 1;
    }
    value = read_16(ptr);
    if (value != 2 && value != 3 && value != 4)
    {
        error(0, 0, "%s: DWARF version %d unhandled", dso->filename, value);
        return 1;
    }
    endprol = ptr + 4;
    endprol += read_32(ptr);
    if (endprol > endcu)
    {
        error(0, 0, "%s: .debug_line CU prologue does not fit into CU", dso->filename);
        return 1;
    }
    opcode_base = ptr[4 + (value >= 4)];
    ptr = dir = ptr + 4 + (value >= 4) + opcode_base;
    value = 1;
    while (*ptr != 0)
    {
        ptr = (unsigned char *)strchr((char *)ptr, 0) + 1;
        ++value;
    }
    dirt = (unsigned char **)alloca(value * (unsigned char *));
    dirt[0] = (unsigned char *)".";
    dirt_cnt = 1;
    ptr = dir;
    while (*ptr != 0)
    {
        dirt[dirt_cnt++] = ptr;
        ptr = (unsigned char *)strchr((char *)ptr, 0) + 1;
    }
    ptr++;
    while (*ptr != 0)
    {
        char *s, *file;
        size_t file_len, dir_len;
        file = (char *)ptr;
        ptr = (unsigned char *)strchr((char *)ptr, 0) + 1;
        value = read_uleb128(ptr);
        if (value >= dirt_cnt)
        {
            error(0, 0, "%s: Wrong directory table index %u", dso->filename, value);
            return 1;
        }
        file_len = strlen(file);
        dir_len = strlen((char *)dirt[value]);
        s = malloc(comp_dir_len + 1 + file_len + 1 + dir_len + 1);
        if (s == NULL)
        {
            error(0, ENOMEM, "%s: Reading file table", dso->filename);
            return 1;
        }
        if (*file == '/')
        {
            memcpy(s, file, file_len + 1);
            if (dest_dir && has_prefix(file, base_dir))
            {
                ++abs_file_cnt;
            }
        }
        if (*dirt[value] == '/')
        {
            memcpy(s, dirt[value], dir_len);
            s[dir_len] = '/';
            memcpy(s + dir_len + 1, file, file_len + 1);
        }
        else
        {
            char *p = s;
            if (comp_dir_len != 0)
            {
                memcpy(s, comp_dir, comp_dir_len);
                s[comp_dir_len] = '/';
                p += comp_dir_len + 1;
            }
            memcpy(p, dirt[value], dir_len);
            p[dir_len] = '/';
            memcpy(p + dir_len + 1, file, file_len + 1);
        }
        canonicalize_path(s, s);
        if (list_file_fd != -1)
        {
            char *p = NULL;
            if (base_dir == NULL)
            {
                p = s;
            }
            if (has_prefix(s, base_dir))
            {
                p = s + strlen(base_dir);
            }
            if (has_prefix(s, dest_dir))
            {
                p = s + strlen(dest_dir);
            }
            if (p)
            {
                size_t size = strlen(p) + 1;
                while (size > 0)
                {
                    ssize_t ret = write(list_file_fd, p, size);
                    if (ret == -1)
                    {
                        break;
                    }
                    size -= ret;
                    p += ret;
                }
            }
        }
        free(s);
        read_uleb128(ptr);
        read_uleb128(ptr);
    }
    ++ptr;
    if (dest_dir)
    {
        unsigned char *srcptr, *buf = NULL;
        size_t base_len = strlen(base_dir);
        size_t dest_len = strlen(dest_dir);
        size_t shrank = 0;
        if (dest_len == base_len)
        {
            abs_file_cnt = 0;
        }
        if (abs_file_cnt)
        {
            srcptr = buf = malloc(ptr - dir);
            memcpy(srcptr, dir, ptr - dir);
            ptr = dir;
        }
        else
        {
            ptr = srcptr = dir;
        }
        while (*srcptr != 0)
        {
            size_t len = strlen((char *)srcptr) + 1;
            const unsigned char *readptr = srcptr;
            char *orig = strdup((const char *)srcptr);
            if (*srcptr == '/' && has_prefix((char *)srcptr, base_dir))
            {
                if (dest_len < base_len)
                {
                    ++abs_dir_cnt;
                }
                memcpy(ptr, dest_dir, dest_len);
                ptr += dest_len;
                readptr += base_len;
            }
            srcptr += len;
            shrank += srcptr - readptr;
            canonicalize_path((char *)readptr, (char *)ptr);
            len = strlen((char *)ptr) + 1;
            shrank -= len;
            ptr += len;
            if (memcmp(orig, ptr - len, len))
            {
                dirty_section(DEBUG_STR);
            }
            free(orig);
        }
        if (shrank > 0)
        {
            if (--shrank == 0)
            {
                error(EXIT_FAILURE, 0, "canonicalization unexpectedly shrank by one character");
            }
            else
            {
                memset(ptr, 'X', shrank);
                ptr += shrank;
                *ptr++ = '\0';
            }
        }
        if (abs_dir_cnt + abs_file_cnt != 0)
        {
            size_t len = (abs_dir_cnt + abs_file_cnt) * (base_len - dest_len);
            if (len == 1)
            {
                error(EXIT_FAILURE, 0, "-b arg has to be either the same length as -d arg, or more than 1 char longer");
            }
            memset(ptr, 'X', len - 1);
            ptr += len - 1;
            *ptr++ = '\0';
        }
        *ptr++ = '\0';
        ++srcptr;
        while (*srcptr != 0)
        {
            size_t len = strlen((char *)srcptr) + 1;
            if (*srcptr == '/' && has_prefix((char *)srcptr, base_dir))
            {
                memcpy(ptr, dest_dir, dest_len);
                if (dest_len < base_len)
                {
                    memmove(ptr + dest_len, srcptr + base_len, len - base_len);
                    ptr += dest_len - base_len;
                }
                dirty_section(DEBUG_STR);
            }
            if (ptr != srcptr)
            {
                memmove(ptr, srcptr, len);
            }
            srcptr += len;
            ptr += len;
            dir = srcptr;
            read_uleb128(srcptr);
            read_uleb128(srcptr);
            read_uleb128(srcptr);
            if (ptr != dir)
            {
                memmove(ptr, dir, srcptr - dir);
            }
            ptr += srcptr - dir;
        }
        *ptr = '\0';
        free(buf);
    }
    return 0;
}