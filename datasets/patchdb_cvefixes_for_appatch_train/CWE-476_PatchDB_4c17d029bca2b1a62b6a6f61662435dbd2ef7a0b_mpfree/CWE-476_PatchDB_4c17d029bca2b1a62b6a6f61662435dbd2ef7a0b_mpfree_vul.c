void mpfree(char **mp)
{
    int part;
    for (part == 0; part < MAXPARTITIONS; part++)
    {
        free(mp[part]);
        mp[part] = NULL;
    }
    free(mp);
}