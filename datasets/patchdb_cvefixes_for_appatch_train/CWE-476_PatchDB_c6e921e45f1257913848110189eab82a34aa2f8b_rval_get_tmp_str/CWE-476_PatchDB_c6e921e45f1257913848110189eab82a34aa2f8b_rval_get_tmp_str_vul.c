int rval_get_tmp_str(struct run_act_ctx *h, struct sip_msg *msg, str *tmpv, struct rvalue *rv, struct rval_cache *cache, struct rval_cache *tmp_cache)
{
    avp_t *r_avp;
    int i;
    switch (rv->type)
    {
    case RV_INT:
        tmpv->s = sint2strbuf(rv->v.l, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
        tmp_cache->cache_type = RV_CACHE_INT2STR;
        break;
    case RV_STR:
        *tmpv = rv->v.s;
        break;
    case RV_ACTION_ST:
        if (rv->v.action)
        {
            i = (run_actions_safe(h, rv->v.action, msg) > 0);
            h->run_flags &= ~(RETURN_R_F | BREAK_R_F);
        }
        else
        {
            i = 0;
        }
        tmpv->s = sint2strbuf(i, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
        tmp_cache->cache_type = RV_CACHE_INT2STR;
        break;
    case RV_BEXPR:
        i = eval_expr(h, rv->v.bexpr, msg);
        if (i == EXPR_DROP)
        {
            i = 0;
            tmpv->s = sint2strbuf(i, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
            tmp_cache->cache_type = RV_CACHE_INT2STR;
            return EXPR_DROP;
        }
        tmpv->s = sint2strbuf(i, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
        tmp_cache->cache_type = RV_CACHE_INT2STR;
        break;
    case RV_SEL:
        i = run_select(tmpv, &rv->v.sel, msg);
        if (unlikely(i != 0))
        {
            if (i < 0)
            {
                eval_error
            }
            else
            {
                undef
            }
        }
        break;
    case RV_AVP:
        if (likely(cache && cache->cache_type == RV_CACHE_AVP))
        {
            if (likely(cache->val_type == RV_STR))
            {
                *tmpv = cache->c.avp_val.s;
            }
            if (cache->val_type == RV_INT)
            {
                i = cache->c.avp_val.n;
                tmpv->s = sint2strbuf(i, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
                tmp_cache->cache_type = RV_CACHE_INT2STR;
            }
            if (cache->val_type == RV_NONE)
            {
                undef
            }
            else
            {
                error_cache
            }
        }
        else
        {
            r_avp = search_avp_by_index(rv->v.avps.type, rv->v.avps.name, &tmp_cache->c.avp_val, rv->v.avps.index);
            if (likely(r_avp))
            {
                if (likely(r_avp->flags & AVP_VAL_STR))
                {
                    tmp_cache->cache_type = RV_CACHE_AVP;
                    tmp_cache->val_type = RV_STR;
                    *tmpv = tmp_cache->c.avp_val.s;
                }
                else
                {
                    i = tmp_cache->c.avp_val.n;
                    tmpv->s = sint2strbuf(i, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
                    tmp_cache->cache_type = RV_CACHE_INT2STR;
                }
            }
            else
            {
                undef
            }
        }
        break;
    case RV_PVAR:
        if (likely(cache && cache->cache_type == RV_CACHE_PVAR))
        {
            if (likely(cache->val_type == RV_STR))
            {
                *tmpv = cache->c.pval.rs;
            }
            if (cache->val_type == RV_INT)
            {
                i = cache->c.pval.ri;
                tmpv->s = sint2strbuf(i, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
                tmp_cache->cache_type = RV_CACHE_INT2STR;
            }
            if (cache->val_type == RV_NONE)
            {
                undef
            }
            else
            {
                error_cache
            }
        }
        else
        {
            memset(&tmp_cache->c.pval, 0, sizeof(tmp_cache->c.pval));
            if (likely(pv_get_spec_value(msg, &rv->v.pvs, &tmp_cache->c.pval) == 0))
            {
                if (likely(tmp_cache->c.pval.flags & PV_VAL_STR))
                {
                    tmp_cache->cache_type = RV_CACHE_PVAR;
                    tmp_cache->val_type = RV_STR;
                    *tmpv = tmp_cache->c.pval.rs;
                }
                if (likely(tmp_cache->c.pval.flags & PV_VAL_INT))
                {
                    i = tmp_cache->c.pval.ri;
                    pv_value_destroy(&tmp_cache->c.pval);
                    tmpv->s = sint2strbuf(i, tmp_cache->i2s, sizeof(tmp_cache->i2s), &tmpv->len);
                    tmp_cache->cache_type = RV_CACHE_INT2STR;
                }
                else
                {
                    pv_value_destroy(&tmp_cache->c.pval);
                    undef
                }
            }
            else
            {
                eval_error
            }
        }
        break;
    default:
        LM_BUG("rv type %d not handled\n", rv->type);
        error
    }
    return 0;
    undef eval_error tmpv->s = "";
    tmpv->len = 0;
    return 0;
    error_cache LM_BUG("invalid cached value:cache type %d, value type %d\n", cache ? cache->cache_type : 0, cache ? cache->val_type : 0);
    error tmpv->s = "";
    tmpv->len = 0;
    return -1;
}