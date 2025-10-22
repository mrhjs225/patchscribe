static int _disable_carbons_handler(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza, void *const userdata)
{
    char *type = xmpp_stanza_get_type(stanza);
    if (g_strcmp0(type, "error") == 0)
    {
        char *error_message = stanza_get_error_message(stanza);
        cons_show_error("Server error disabling message carbons: %s", error_message);
        log_debug("Error disabling carbons: %s", error_message);
    }
    else
    {
        log_debug("Message carbons disabled.");
    }
    return 0;
}