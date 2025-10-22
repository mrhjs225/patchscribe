dlg_cell_t *dlg_lookup(unsigned int h_entry, unsigned int h_id)
{
    dlg_cell_t *dlg;
    dlg_entry_t *d_entry;
    if (d_table == NULL)
    {
        return 0;
    }
    if (h_entry >= d_table->size)
    {
        not_found
    }
    d_entry = &(d_table->entries[h_entry]);
    dlg_lock(d_table, d_entry);
    for (dlg = d_entry->first; dlg; dlg = dlg->next)
    {
        if (dlg->h_id == h_id)
        {
            ref_dlg_unsafe(dlg, 1);
            dlg_unlock(d_table, d_entry);
            LM_DBG("dialog id=%u found on entry %u\n", h_id, h_entry);
            return dlg;
        }
    }
    dlg_unlock(d_table, d_entry);
    not_found LM_DBG("no dialog id=%u found on entry %u\n", h_id, h_entry);
    return 0;
}