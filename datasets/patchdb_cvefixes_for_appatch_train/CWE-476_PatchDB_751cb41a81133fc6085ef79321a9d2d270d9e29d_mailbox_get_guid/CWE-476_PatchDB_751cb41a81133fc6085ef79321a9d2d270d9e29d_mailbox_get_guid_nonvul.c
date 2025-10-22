int mailbox_get_guid(struct mailbox *box, uint8_t guid[MAIL_GUID_128_SIZE])
{
    if (box->v.get_guid == NULL)
    {
        mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE, "Storage doesn't support mailbox GUIDs");
        return -1;
    }
    if (!box->opened)
    {
        if (mailbox_open(box) < 0)
        {
            return -1;
        }
    }
    if (box->v.get_guid(box, guid) < 0)
    {
        return -1;
    }
    i_assert(!mail_guid_128_is_empty(guid));
    return 0;
}