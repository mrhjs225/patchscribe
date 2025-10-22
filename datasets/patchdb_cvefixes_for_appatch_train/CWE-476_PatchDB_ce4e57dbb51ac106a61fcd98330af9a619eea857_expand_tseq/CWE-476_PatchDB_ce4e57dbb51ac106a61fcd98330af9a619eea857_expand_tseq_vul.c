static int expand_tseq(void *log, struct sbg_script *s, int *nb_ev_max, int64_t t0, struct sbg_script_tseq *tseq)
{
    int i, r;
    struct sbg_script_definition *def;
    struct sbg_script_tseq *be;
    struct sbg_script_event *ev;
    if (tseq->lock++)
    {
        av_log(log, AV_LOG_ERROR, "Recursion loop on \"%.*s\"\n", tseq->name_len, tseq->name);
        return AVERROR(EINVAL);
    }
    t0 += tseq->ts.t;
    for (i = 0; i < s->nb_def; i++)
    {
        if (s->def[i].name_len == tseq->name_len && !memcmp(s->def[i].name, tseq->name, tseq->name_len))
        {
            break;
        }
    }
    if (i >= s->nb_def)
    {
        av_log(log, AV_LOG_ERROR, "Tone-set \"%.*s\" not defined\n", tseq->name_len, tseq->name);
        return AVERROR(EINVAL);
    }
    def = &s->def[i];
    if (def->type == 'B')
    {
        be = s->block_tseq + def->elements;
        for (i = 0; i < def->nb_elements; i++)
        {
            r = expand_tseq(log, s, nb_ev_max, t0, &be[i]);
            if (r < 0)
            {
                return r;
            }
        }
    }
    else
    {
        ev = alloc_array_elem((void **)&s->events, sizeof(*ev), &s->nb_events, nb_ev_max);
        ev->ts = tseq->ts.t;
        ev->elements = def->elements;
        ev->nb_elements = def->nb_elements;
        ev->fade = tseq->fade;
    }
    tseq->lock--;
    return 0;
}