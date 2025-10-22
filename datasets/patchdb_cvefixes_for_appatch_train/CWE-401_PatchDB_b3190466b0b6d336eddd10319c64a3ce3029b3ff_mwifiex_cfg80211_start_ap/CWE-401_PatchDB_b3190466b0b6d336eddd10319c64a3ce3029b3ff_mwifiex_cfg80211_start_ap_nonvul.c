static int mwifiex_cfg80211_start_ap(struct wiphy *wiphy, struct net_device *dev, struct cfg80211_ap_settings *params)
{
    struct mwifiex_uap_bss_param *bss_cfg;
    struct mwifiex_private *priv = mwifiex_netdev_get_priv(dev);
    if (priv->bss_type != MWIFIEX_BSS_TYPE_UAP)
    {
        return -1;
    }
    if (mwifiex_set_mgmt_ies(priv, params))
    {
        return -1;
    }
    bss_cfg = kzalloc(sizeof(mwifiex_uap_bss_param), GFP_KERNEL);
    if (!bss_cfg)
    {
        return -ENOMEM;
    }
    mwifiex_set_sys_config_invalid_data(bss_cfg);
    if (params->beacon_interval)
    {
        bss_cfg->beacon_period = params->beacon_interval;
    }
    if (params->dtim_period)
    {
        bss_cfg->dtim_period = params->dtim_period;
    }
    if (params->ssid && params->ssid_len)
    {
        memcpy(bss_cfg->ssid.ssid, params->ssid, params->ssid_len);
        bss_cfg->ssid.ssid_len = params->ssid_len;
    }
    switch (params->hidden_ssid)
    {
    case NL80211_HIDDEN_SSID_NOT_IN_USE:
        bss_cfg->bcast_ssid_ctl = 1;
        break;
    case NL80211_HIDDEN_SSID_ZERO_LEN:
        bss_cfg->bcast_ssid_ctl = 0;
        break;
    case NL80211_HIDDEN_SSID_ZERO_CONTENTS:
    default:
        kfree(bss_cfg);
        return -EINVAL;
    }
    if (mwifiex_set_secure_params(priv, bss_cfg, params))
    {
        kfree(bss_cfg);
        wiphy_err(wiphy, "Failed to parse secuirty parameters!\n");
        return -1;
    }
    if (mwifiex_send_cmd_sync(priv, HostCmd_CMD_UAP_BSS_STOP, HostCmd_ACT_GEN_SET, 0, NULL))
    {
        wiphy_err(wiphy, "Failed to stop the BSS\n");
        kfree(bss_cfg);
        return -1;
    }
    if (mwifiex_send_cmd_async(priv, HostCmd_CMD_UAP_SYS_CONFIG, HostCmd_ACT_GEN_SET, UAP_BSS_PARAMS_I, bss_cfg))
    {
        wiphy_err(wiphy, "Failed to set the SSID\n");
        kfree(bss_cfg);
        return -1;
    }
    kfree(bss_cfg);
    if (mwifiex_send_cmd_async(priv, HostCmd_CMD_UAP_BSS_START, HostCmd_ACT_GEN_SET, 0, NULL))
    {
        wiphy_err(wiphy, "Failed to start the BSS\n");
        return -1;
    }
    return 0;
}