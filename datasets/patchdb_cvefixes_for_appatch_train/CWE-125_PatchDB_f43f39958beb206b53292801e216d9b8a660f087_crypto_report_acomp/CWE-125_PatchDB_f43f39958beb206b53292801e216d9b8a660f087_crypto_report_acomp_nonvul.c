static int crypto_report_acomp(struct sk_buff *skb, struct crypto_alg *alg)
{
    struct crypto_report_acomp racomp;
    strncpy(racomp.type, "acomp", sizeof(racomp.type));
    if (nla_put(skb, CRYPTOCFGA_REPORT_ACOMP, sizeof(crypto_report_acomp), &racomp))
    {
        nla_put_failure
    }
    return 0;
    nla_put_failure return -EMSGSIZE;
}