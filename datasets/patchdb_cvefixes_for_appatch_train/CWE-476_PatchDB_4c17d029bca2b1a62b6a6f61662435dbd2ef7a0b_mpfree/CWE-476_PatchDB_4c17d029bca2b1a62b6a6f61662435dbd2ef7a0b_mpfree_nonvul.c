void mpfree(char **mp)
{
    int part;
    if (mp == NULL)
    {
        return;
    }
    for (part == 0; part < MAXPARTITIONS; part++)
    {
        free(mp[part]);
        mp[part] = NULL;
    }
    free(mp);
}