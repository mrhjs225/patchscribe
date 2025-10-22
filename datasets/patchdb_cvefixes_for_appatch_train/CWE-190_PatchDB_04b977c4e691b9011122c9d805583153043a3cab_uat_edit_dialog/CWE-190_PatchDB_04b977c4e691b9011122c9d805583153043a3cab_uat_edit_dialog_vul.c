static void uat_edit_dialog(uat_t *uat, gint row, gboolean copy)
{
    GtkWidget *win, *main_tb, *main_vb, *bbox, *bt_cancel, *bt_ok;
    struct _uat_dlg_data *dd = g_malloc(sizeof(_uat_dlg_data));
    uat_field_t *f = uat->fields;
    guint colnum;
    GtkTooltips *tooltips;
    tooltips = gtk_tooltips_new();
    dd->entries = g_ptr_array_new();
    dd->win = dlg_conf_window_new(ep_strdup_printf("%s: %s", uat->name, (row == -1 ? "New" : "Edit")));
    dd->uat = uat;
    if (copy && row >= 0)
    {
        dd->rec = g_malloc0(uat->record_size);
        if (uat->copy_cb)
        {
            uat->copy_cb(dd->rec, UAT_INDEX_PTR(uat, row), uat->record_size);
        }
        dd->is_new = TRUE;
    }
    if (row >= 0)
    {
        dd->rec = UAT_INDEX_PTR(uat, row);
        dd->is_new = FALSE;
    }
    else
    {
        dd->rec = g_malloc0(uat->record_size);
        dd->is_new = TRUE;
    }
    dd->row = row;
    dd->tobe_freed = g_ptr_array_new();
    win = dd->win;
    gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
    gtk_window_resize(GTK_WINDOW(win), 400, 30 * (uat->ncols + 2));
    main_vb = gtk_vbox_new(FALSE, 5);
    gtk_container_add(GTK_CONTAINER(win), main_vb);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 6);
    main_tb = gtk_table_new(uat->ncols + 1, 2, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
    gtk_table_set_row_spacings(GTK_TABLE(main_tb), 5);
    gtk_table_set_col_spacings(GTK_TABLE(main_tb), 10);
    bbox = dlg_button_row_new(GTK_STOCK_CANCEL, GTK_STOCK_OK, NULL);
    gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
    bt_ok = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
    g_signal_connect(bt_ok, "clicked", G_CALLBACK(uat_dlg_cb), dd);
    bt_cancel = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
    g_signal_connect(bt_cancel, "clicked", G_CALLBACK(uat_cancel_dlg_cb), dd);
    window_set_cancel_button(win, bt_cancel, NULL);
    for (colnum = 0; colnum < uat->ncols; colnum++)
    {
        GtkWidget *entry, *label, *event_box;
        char *text = fld_tostr(dd->rec, &(f[colnum]));
        event_box = gtk_event_box_new();
        label = gtk_label_new(ep_strdup_printf("%s:", f[colnum].title));
        if (f[colnum].desc != NULL)
        {
            gtk_tooltips_set_tip(tooltips, event_box, f[colnum].desc, NULL);
        }
        gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
        gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box, 0, 1, colnum + 1, colnum + 2);
        gtk_container_add(GTK_CONTAINER(event_box), label);
        switch (f[colnum].mode)
        {
        case PT_TXTMOD_STRING:
        case PT_TXTMOD_HEXBYTES:
        {
            entry = gtk_entry_new();
            g_ptr_array_add(dd->entries, entry);
            gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, colnum + 1, colnum + 2);
            if (!dd->is_new || copy)
            {
                gtk_entry_set_text(GTK_ENTRY(entry), text);
            }
            dlg_set_activate(entry, bt_ok);
            break;
        }
        case PT_TXTMOD_ENUM:
        {
            GtkWidget *combo_box;
            int idx;
            const value_string *enum_vals = f[colnum].fld_data;
            int *valptr = g_malloc(sizeof(int *));
            combo_box = gtk_combo_box_new_text();
            *valptr = -1;
            for (idx = 0; enum_vals[idx].strptr != NULL; idx++)
            {
                const char *str = enum_vals[idx].strptr;
                gtk_combo_box_append_text(GTK_COMBO_BOX(combo_box), str);
                if (g_str_equal(str, text))
                {
                    *valptr = idx;
                }
            }
            g_ptr_array_add(dd->entries, valptr);
            g_ptr_array_add(dd->tobe_freed, valptr);
            if (*valptr != -1)
            {
                gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), *valptr);
            }
            g_signal_connect(combo_box, "changed", G_CALLBACK(fld_combo_box_changed_cb), valptr);
            gtk_table_attach_defaults(GTK_TABLE(main_tb), combo_box, 1, 2, colnum + 1, colnum + 2);
            break;
        }
        default:
            g_assert_not_reached();
            return;
        }
    }
    gtk_widget_grab_default(bt_ok);
    gtk_widget_show_all(win);
}