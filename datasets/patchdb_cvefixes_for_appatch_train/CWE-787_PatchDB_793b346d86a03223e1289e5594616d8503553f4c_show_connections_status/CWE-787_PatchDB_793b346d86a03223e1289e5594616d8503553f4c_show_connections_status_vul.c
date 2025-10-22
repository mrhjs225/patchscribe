void show_connections_status(void)
{
    struct connection *c;
    int count, i;
    struct connection **array;
    count = 0;
    for (c = connections; c != NULL; c = c->ac_next)
    {
        count++;
    }
    array = alloc_bytes(sizeof(connection *) * count, "connection array");
    count = 0;
    for (c = connections; c != NULL; c = c->ac_next)
    {
        array[count++] = c;
    }
    qsort(array, count, sizeof(connection *), connection_compare_qsort);
    for (i = 0; i < count; i++)
    {
        const char *ifn;
        char instance[1 + 10 + 1];
        char prio[POLICY_PRIO_BUF];
        c = array[i];
        ifn = oriented(*c) ? c->interface->ip_dev->id_rname : "";
        instance[0] = '\0';
        if (c->kind == CK_INSTANCE && c->instance_serial != 0)
        {
            snprintf(instance, sizeof(instance), "[%lu]", c->instance_serial);
        }
        {
            char topo[CONN_BUF_LEN];
            struct spd_route *sr = &c->spd;
            int num = 0;
            while (sr != NULL)
            {
                char srcip[ADDRTOT_BUF], dstip[ADDRTOT_BUF];
                char thissemi[3 + sizeof("myup=")];
                char thatsemi[3 + sizeof("hisup=")];
                char thisxauthsemi[XAUTH_USERNAME_LEN + sizeof("myxauthuser=")];
                char thatxauthsemi[XAUTH_USERNAME_LEN + sizeof("hisxauthuser=")];
                char thiscertsemi[3 + sizeof("mycert=") + PATH_MAX];
                char thatcertsemi[3 + sizeof("hiscert=") + PATH_MAX];
                char *thisup, *thatup;
                (void)format_connection(topo, sizeof(topo), c, sr);
                whack_log(RC_COMMENT, "\"%s\"%s: %s; %s; eroute owner: #%lu", c->name, instance, topo, enum_name(&routing_story, sr->routing), sr->eroute_owner);
                if (addrbytesptr(&c->spd.this.host_srcip, NULL) == 0 || isanyaddr(&c->spd.this.host_srcip))
                {
                    strcpy(srcip, "unset");
                }
                else
                {
                    addrtot(&sr->this.host_srcip, 0, srcip, sizeof(srcip));
                }
                if (addrbytesptr(&c->spd.that.host_srcip, NULL) == 0 || isanyaddr(&c->spd.that.host_srcip))
                {
                    strcpy(dstip, "unset");
                }
                else
                {
                    addrtot(&sr->that.host_srcip, 0, dstip, sizeof(dstip));
                }
                thissemi[0] = '\0';
                thisup = thissemi;
                if (sr->this.updown)
                {
                    thissemi[0] = ';';
                    thissemi[1] = ' ';
                    thissemi[2] = '\0';
                    strcat(thissemi, "myup=");
                    thisup = sr->this.updown;
                }
                thatsemi[0] = '\0';
                thatup = thatsemi;
                if (sr->that.updown)
                {
                    thatsemi[0] = ';';
                    thatsemi[1] = ' ';
                    thatsemi[2] = '\0';
                    strcat(thatsemi, "hisup=");
                    thatup = sr->that.updown;
                }
                thiscertsemi[0] = '\0';
                if (sr->this.cert_filename)
                {
                    snprintf(thiscertsemi, sizeof(thiscertsemi) - 1, "; mycert=%s", sr->this.cert_filename);
                }
                thatcertsemi[0] = '\0';
                if (sr->that.cert_filename)
                {
                    snprintf(thatcertsemi, sizeof(thatcertsemi) - 1, "; hiscert=%s", sr->that.cert_filename);
                }
                whack_log(RC_COMMENT, "\"%s\"%s:     myip=%s; hisip=%s%s%s%s%s%s%s;", c->name, instance, srcip, dstip, thissemi, thisup, thatsemi, thatup, thiscertsemi, thatcertsemi);
                if (sr->this.xauth_name || sr->that.xauth_name)
                {
                    thisxauthsemi[0] = '\0';
                    if (sr->this.xauth_name)
                    {
                        snprintf(thisxauthsemi, sizeof(thisxauthsemi) - 1, "myxauthuser=%s; ", sr->this.xauth_name);
                    }
                    thatxauthsemi[0] = '\0';
                    if (sr->that.xauth_name)
                    {
                        snprintf(thatxauthsemi, sizeof(thatxauthsemi) - 1, "hisxauthuser=%s; ", sr->that.xauth_name);
                    }
                    whack_log(RC_COMMENT, "\"%s\"%s:     xauth info: %s%s", c->name, instance, thisxauthsemi, thatxauthsemi);
                }
                sr = sr->next;
                num++;
            }
        }
        if (c->spd.this.ca.ptr != NULL || c->spd.that.ca.ptr != NULL)
        {
            char this_ca[IDTOA_BUF], that_ca[IDTOA_BUF];
            dntoa_or_null(this_ca, IDTOA_BUF, c->spd.this.ca, "%any");
            dntoa_or_null(that_ca, IDTOA_BUF, c->spd.that.ca, "%any");
            whack_log(RC_COMMENT, "\"%s\"%s:   CAs: '%s'...'%s'", c->name, instance, this_ca, that_ca);
        }
        whack_log(RC_COMMENT, "\"%s\"%s:   ike_life: %lus; ipsec_life: %lus;"
                              " rekey_margin: %lus; rekey_fuzz: %lu%%; keyingtries: %lu",
                  c->name, instance, (unsigned long)c->sa_ike_life_seconds, (unsigned long)c->sa_ipsec_life_seconds, (unsigned long)c->sa_rekey_margin, (unsigned long)c->sa_rekey_fuzz, (unsigned long)c->sa_keying_tries);
        if (c->policy_next)
        {
            whack_log(RC_COMMENT, "\"%s\"%s:   policy_next: %s", c->name, instance, c->policy_next->name);
        }
        fmt_policy_prio(c->prio, prio);
        whack_log(RC_COMMENT, "\"%s\"%s:   policy: %s%s%s; prio: %s; interface: %s; ", c->name, instance, prettypolicy(c->policy), c->spd.this.key_from_DNS_on_demand ? "+lKOD" : "", c->spd.that.key_from_DNS_on_demand ? "+rKOD" : "", prio, ifn);
        if (c->dpd_timeout > 0 || DBGP(DBG_DPD))
        {
            whack_log(RC_COMMENT, "\"%s\"%s:   dpd: %s; delay:%lu; timeout:%lu; ", c->name, instance, enum_name(&dpd_action_names, c->dpd_action), (unsigned long)c->dpd_delay, (unsigned long)c->dpd_timeout);
        }
        if (c->extra_debugging)
        {
            whack_log(RC_COMMENT, "\"%s\"%s:   debug: %s", c->name, instance, bitnamesof(debug_bit_names, c->extra_debugging));
        }
        whack_log(RC_COMMENT, "\"%s\"%s:   newest ISAKMP SA: #%ld; newest IPsec SA: #%ld; ", c->name, instance, c->newest_isakmp_sa, c->newest_ipsec_sa);
        if (c->connalias)
        {
            whack_log(RC_COMMENT, "\"%s\"%s:   aliases: %s\n", c->name, instance, c->connalias);
        }
        ike_alg_show_connection(c, instance);
        kernel_alg_show_connection(c, instance);
    }
    pfree(array);
}