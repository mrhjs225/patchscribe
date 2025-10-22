void kerberos5_forward(Authenticator *ap)
{
    krb5_error_code ret;
    krb5_ccache ccache;
    krb5_creds creds;
    krb5_kdc_flags flags;
    krb5_data out_data;
    krb5_principal principal;
    ret = krb5_cc_default(context, &ccache);
    if (ret)
    {
        if (auth_debug_mode)
        {
            printf("KerberosV5: could not get default ccache: %s\r\n", krb5_get_err_text(context, ret));
        }
        return;
    }
    ret = krb5_cc_get_principal(context, ccache, &principal);
    if (ret)
    {
        if (auth_debug_mode)
        {
            printf("KerberosV5: could not get principal: %s\r\n", krb5_get_err_text(context, ret));
        }
        return;
    }
    memset(&creds, 0, sizeof(creds));
    creds.client = principal;
    ret = krb5_build_principal(context, &creds.server, strlen(principal->realm), principal->realm, "krbtgt", principal->realm, NULL);
    if (ret)
    {
        if (auth_debug_mode)
        {
            printf("KerberosV5: could not get principal: %s\r\n", krb5_get_err_text(context, ret));
        }
        return;
    }
    creds.times.endtime = 0;
    flags.i = 0;
    flags.b.forwarded = 1;
    if (forward_flags & OPTS_FORWARDABLE_CREDS)
    {
        flags.b.forwardable = 1;
    }
    ret = krb5_get_forwarded_creds(context, auth_context, ccache, flags.i, RemoteHostName, &creds, &out_data);
    if (ret)
    {
        if (auth_debug_mode)
        {
            printf("Kerberos V5: error gettting forwarded creds: %s\r\n", krb5_get_err_text(context, ret));
        }
        return;
    }
    if (!Data(ap, KRB_FORWARD, out_data.data, out_data.length))
    {
        if (auth_debug_mode)
        {
            printf("Not enough room for authentication data\r\n");
        }
    }
    else
    {
        if (auth_debug_mode)
        {
            printf("Forwarded local Kerberos V5 credentials to server\r\n");
        }
    }
}