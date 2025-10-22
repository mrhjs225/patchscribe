void eel_g_settings_add_auto_int(GSettings *settings, const char *key, int *storage)
{
    char *signal;
    *storage = g_settings_get_int(settings, key);
    signal = g_strconcat("changed::", key, NULL);
    g_signal_connect(settings, signal, G_CALLBACK(update_auto_int), storage);
    g_free(signal);
}