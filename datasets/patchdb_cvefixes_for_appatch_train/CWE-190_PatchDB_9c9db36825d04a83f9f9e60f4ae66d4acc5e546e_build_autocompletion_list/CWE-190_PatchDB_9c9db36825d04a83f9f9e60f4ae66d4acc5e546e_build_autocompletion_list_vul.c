static gboolean build_autocompletion_list(GtkWidget *filter_te, GtkWidget *treeview, GtkWidget *popup_win, const gchar *protocol_name, gboolean protocols_only, gboolean *stop_propagation)
{
    void *cookie, *cookie2;
    protocol_t *protocol;
    unsigned int protocol_name_len;
    header_field_info *hfinfo;
    gint count = 0;
    gboolean exact_match = FALSE;
    const gchar *first = NULL;
    int i;
    protocol_name_len = strlen(protocol_name);
    for (i = proto_get_first_protocol(&cookie); i != -1; i = proto_get_next_protocol(&cookie))
    {
        protocol = find_protocol_by_id(i);
        if (!proto_is_protocol_enabled(protocol))
        {
            continue;
        }
        if (protocols_only)
        {
            const gchar *name = proto_get_protocol_filter_name(i);
            if (!g_ascii_strncasecmp(protocol_name, name, protocol_name_len))
            {
                add_to_autocompletion_list(treeview, name);
                if (strlen(name) == protocol_name_len)
                {
                    exact_match = TRUE;
                }
                count++;
                if (count == 1)
                {
                    first = name;
                }
            }
        }
        else
        {
            hfinfo = proto_registrar_get_nth(i);
            for (hfinfo = proto_get_first_protocol_field(i, &cookie2); hfinfo != NULL; hfinfo = proto_get_next_protocol_field(&cookie2))
            {
                if (hfinfo->same_name_prev != NULL)
                {
                    continue;
                }
                if (!g_ascii_strncasecmp(protocol_name, hfinfo->abbrev, protocol_name_len))
                {
                    add_to_autocompletion_list(treeview, hfinfo->abbrev);
                    if (strlen(hfinfo->abbrev) == protocol_name_len)
                    {
                        exact_match = TRUE;
                    }
                    count++;
                    if (count == 1)
                    {
                        first = hfinfo->abbrev;
                    }
                }
            }
        }
    }
    if (count == 1 && !exact_match && stop_propagation && strncmp(protocol_name, first, protocol_name_len) == 0)
    {
        *stop_propagation = check_select_region(filter_te, popup_win, first, protocol_name_len);
    }
    if (count == 0 || (count == 1 && exact_match && strncmp(protocol_name, first, protocol_name_len) == 0))
    {
        return FALSE;
    }
    return TRUE;
}