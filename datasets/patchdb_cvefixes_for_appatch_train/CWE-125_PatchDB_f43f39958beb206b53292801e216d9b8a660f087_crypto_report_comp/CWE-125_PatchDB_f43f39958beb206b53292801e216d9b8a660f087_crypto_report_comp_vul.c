static int crypto_report_comp(struct sk_buff *skb, struct crypto_alg *alg)
{
    struct crypto_report_comp rcomp;
    strlcpy(rcomp.type, "compression", sizeof(rcomp.type));
    if (nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS, sizeof(crypto_report_comp), &rcomp))
    {
        nla_put_failure
    }
    return 0;
    nla_put_failure return -EMSGSIZE;
}