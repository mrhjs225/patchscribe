static char *nautilus_link_get_link_uri_from_desktop(GKeyFile *key_file, const char *desktop_file_uri)
{
    GFile *file, *parent;
    char *type;
    char *retval;
    char *scheme;
    retval = NULL;
    type = g_key_file_get_string(key_file, MAIN_GROUP, "Type", NULL);
    if (type == NULL)
    {
        return NULL;
    }
    if (strcmp(type, "URL") == 0)
    {
        retval = g_key_file_get_string(key_file, MAIN_GROUP, "Exec", NULL);
    }
    if ((strcmp(type, NAUTILUS_LINK_GENERIC_TAG) == 0) || (strcmp(type, NAUTILUS_LINK_MOUNT_TAG) == 0) || (strcmp(type, NAUTILUS_LINK_TRASH_TAG) == 0) || (strcmp(type, NAUTILUS_LINK_HOME_TAG) == 0))
    {
        retval = g_key_file_get_string(key_file, MAIN_GROUP, "URL", NULL);
    }
    g_free(type);
    if (retval != NULL && desktop_file_uri != NULL)
    {
        scheme = g_uri_parse_scheme(retval);
        if (scheme == NULL)
        {
            file = g_file_new_for_uri(desktop_file_uri);
            parent = g_file_get_parent(file);
            g_object_unref(file);
            if (parent != NULL)
            {
                file = g_file_resolve_relative_path(parent, retval);
                g_free(retval);
                retval = g_file_get_uri(file);
                g_object_unref(file);
                g_object_unref(parent);
            }
        }
    }
    return retval;
}