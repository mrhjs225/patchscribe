static void pppdump_close(wtap *wth)
{
    pppdump_t *state;
    state = wth->capture.generic;
    if (state->precs)
    {
        g_list_foreach(state->precs, simple_g_free, NULL);
        g_list_free(state->precs);
    }
    if (state->seek_state)
    {
        g_free(state->seek_state);
    }
    if (state->pids)
    {
        unsigned int i;
        for (i = 0; i < g_ptr_array_len(state->pids); i++)
        {
            g_free(g_ptr_array_index(state->pids, i));
        }
        g_ptr_array_free(state->pids, TRUE);
    }
    g_free(state);
}