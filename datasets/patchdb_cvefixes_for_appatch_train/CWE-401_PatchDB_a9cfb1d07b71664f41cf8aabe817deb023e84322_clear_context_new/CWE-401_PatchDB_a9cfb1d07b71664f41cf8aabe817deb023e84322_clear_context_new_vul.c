CLEAR_CONTEXT *clear_context_new(BOOL Compressor)
{
    CLEAR_CONTEXT *clear;
    clear = (CLEAR_CONTEXT *)calloc(1, sizeof(CLEAR_CONTEXT));
    if (clear)
    {
        clear->Compressor = Compressor;
        clear->nsc = nsc_context_new();
        if (!clear->nsc)
        {
            return NULL;
        }
        nsc_context_set_pixel_format(clear->nsc, RDP_PIXEL_FORMAT_R8G8B8);
        clear->TempSize = 512 * 512 * 4;
        clear->TempBuffer = (BYTE *)malloc(clear->TempSize);
        clear_context_reset(clear);
    }
    return clear;
}