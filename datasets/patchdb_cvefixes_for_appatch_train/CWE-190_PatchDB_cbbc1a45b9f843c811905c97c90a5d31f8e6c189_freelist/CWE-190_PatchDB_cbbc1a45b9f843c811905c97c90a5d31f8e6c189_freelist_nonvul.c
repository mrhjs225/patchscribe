static void freelist(char **cpp)
{
    size_t i;
    if (cpp == NULL)
    {
        return;
    }
    for (i = 0; cpp[i] != NULL; ++i)
    {
        free(cpp[i]);
        cpp[i] = NULL;
    }
}