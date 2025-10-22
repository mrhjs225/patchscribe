static int client_x11_display_valid(const char *display)
{
    size_t i, dlen;
    dlen = strlen(display);
    for (i = 0; i < dlen; i++)
    {
        if (!isalnum((u_char)display[i]) && strchr(SSH_X11_VALID_DISPLAY_CHARS, display[i]) == NULL)
        {
            debug("Invalid character '%c' in DISPLAY", display[i]);
            return 0;
        }
    }
    return 1;
}