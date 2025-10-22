static gboolean autocompletion_list_lookup(GtkWidget *filter_te, GtkWidget *popup_win, GtkWidget *list, const gchar *str, gboolean *stop_propagation)
{
    GtkRequisition requisition;
    GtkListStore *store;
    GtkTreeIter iter;
    GtkTreeSelection *selection;
    gchar *curr_str;
    unsigned int str_len = (unsigned int)strlen(str);
    gchar *first = NULL;
    gint count = 0;
    gboolean loop = TRUE;
    gboolean exact_match = FALSE;
    store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
    if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
    {
        selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
        {
            gtk_tree_model_get(GTK_TREE_MODEL(store), &iter, 0, &curr_str, -1);
            if (!g_ascii_strncasecmp(str, curr_str, str_len))
            {
                loop = gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
                if (strlen(curr_str) == str_len)
                {
                    exact_match = TRUE;
                }
                count++;
                if (count == 1)
                {
                    first = g_strdup(curr_str);
                }
            }
            else
            {
                loop = gtk_list_store_remove(store, &iter);
            }
            g_free(curr_str);
        }
        loop;
        if (count == 1 && !exact_match && strncmp(str, first, str_len) == 0)
        {
            *stop_propagation = check_select_region(filter_te, popup_win, first, str_len);
        }
        if ((count == 1 && exact_match && strncmp(str, first, str_len) == 0) || !gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
        {
            g_free(first);
            return FALSE;
        }
        g_free(first);
        gtk_widget_size_request(list, &requisition);
        gtk_widget_set_size_request(popup_win, popup_win->allocation.width, (requisition.height < 200 ? requisition.height + 8 : 200));
        gtk_window_resize(GTK_WINDOW(popup_win), popup_win->allocation.width, (requisition.height < 200 ? requisition.height + 8 : 200));
        return TRUE;
    }
    return FALSE;
}