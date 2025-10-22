static int dmxProcRenderSetPictureFilter(ClientPtr client)
{
    DMXScreenInfo *dmxScreen;
    PicturePtr pPicture;
    dmxPictPrivPtr pPictPriv;
    char *filter;
    XFixed *params;
    int nparams;
    REQUEST(xRenderSetPictureFilterReq);
    REQUEST_AT_LEAST_SIZE(xRenderSetPictureFilterReq);
    VERIFY_PICTURE(pPicture, stuff->picture, client, DixWriteAccess);
    dmxScreen = &dmxScreens[pPicture->pDrawable->pScreen->myNum];
    pPictPriv = DMX_GET_PICT_PRIV(pPicture);
    if (pPictPriv->pict)
    {
        filter = (char *)(stuff + 1);
        params = (XFixed *)(filter + ((stuff->nbytes + 3) & ~3));
        nparams = ((XFixed *)stuff + client->req_len) - params;
        XRenderSetPictureFilter(dmxScreen->beDisplay, pPictPriv->pict, filter, params, nparams);
        dmxSync(dmxScreen, FALSE);
    }
    return dmxSaveRenderVector[stuff->renderReqType](client);
}