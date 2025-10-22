EXPORTED int carddav_writecard(struct carddav_db *carddavdb, struct carddav_data *cdata, struct vparse_card *vcard)
{
    struct vparse_entry *ventry;
    strarray_t emails = STRARRAY_INITIALIZER;
    strarray_t member_uids = STRARRAY_INITIALIZER;
    for (ventry = vcard->properties; ventry; ventry = ventry->next)
    {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;
        if (!name)
        {
            continue;
        }
        if (!propval)
        {
            continue;
        }
        if (!strcmp(name, "uid"))
        {
            cdata->vcard_uid = propval;
        }
        if (!strcmp(name, "n"))
        {
            cdata->name = propval;
        }
        if (!strcmp(name, "fn"))
        {
            cdata->fullname = propval;
        }
        if (!strcmp(name, "nickname"))
        {
            cdata->nickname = propval;
        }
        if (!strcmp(name, "email"))
        {
            int ispref = 0;
            struct vparse_param *param;
            for (param = ventry->params; param; param = param->next)
            {
                if (!strcasecmp(param->name, "type") && !strcasecmp(param->value, "pref"))
                {
                    ispref = 1;
                }
            }
            strarray_append(&emails, propval);
            strarray_append(&emails, ispref ? "1" : "");
        }
        if (!strcmp(name, "x-addressbookserver-member"))
        {
            if (strncmp(propval, "urn:uuid:", 9))
            {
                continue;
            }
            strarray_append(&member_uids, propval + 9);
            strarray_append(&member_uids, "");
        }
        if (!strcmp(name, "x-fm-otheraccount-member"))
        {
            if (strncmp(propval, "urn:uuid:", 9))
            {
                continue;
            }
            struct vparse_param *param = vparse_get_param(ventry, "userid");
            if (!param)
            {
                continue;
            }
            strarray_append(&member_uids, propval + 9);
            strarray_append(&member_uids, param->value);
        }
        if (!strcmp(name, "x-addressbookserver-kind"))
        {
            if (!strcasecmp(propval, "group"))
            {
                cdata->kind = CARDDAV_KIND_GROUP;
            }
        }
    }
    int r = carddav_write(carddavdb, cdata);
    if (!r)
    {
        r = carddav_write_emails(carddavdb, cdata->dav.rowid, &emails);
    }
    if (!r)
    {
        r = carddav_write_groups(carddavdb, cdata->dav.rowid, &member_uids);
    }
    strarray_fini(&emails);
    strarray_fini(&member_uids);
    return r;
}