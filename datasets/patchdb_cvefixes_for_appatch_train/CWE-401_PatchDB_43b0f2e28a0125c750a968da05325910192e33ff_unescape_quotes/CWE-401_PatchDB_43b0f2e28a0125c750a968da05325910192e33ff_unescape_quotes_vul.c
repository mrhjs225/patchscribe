static void unescape_quotes(char *source, int quote, int escape)
{
    char *p;
    char *destination, *tmp;
    assert(source);
    destination = calloc(1, strlen(source) + 1);
    if (!destination)
    {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    tmp = destination;
    for (p = source; *p; p++)
    {
        char c;
        if (*p == escape && *(p + 1) && quote == *(p + 1))
        {
            c = *(p + 1);
            p++;
        }
        else
        {
            c = *p;
        }
        *tmp = c;
        tmp++;
    }
    *tmp = '\0';
    strcpy(source, destination);
}