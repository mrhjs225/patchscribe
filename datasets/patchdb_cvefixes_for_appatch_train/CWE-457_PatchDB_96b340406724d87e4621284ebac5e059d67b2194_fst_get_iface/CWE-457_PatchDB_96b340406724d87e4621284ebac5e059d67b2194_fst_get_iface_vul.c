static int fst_get_iface(struct fst_card_info *card, struct fst_port_info *port, struct ifreq *ifr)
{
    sync_serial_settings sync;
    int i;
    switch (port->hwif)
    {
    case E1:
        ifr->ifr_settings.type = IF_IFACE_E1;
        break;
    case T1:
        ifr->ifr_settings.type = IF_IFACE_T1;
        break;
    case V35:
        ifr->ifr_settings.type = IF_IFACE_V35;
        break;
    case V24:
        ifr->ifr_settings.type = IF_IFACE_V24;
        break;
    case X21D:
        ifr->ifr_settings.type = IF_IFACE_X21D;
        break;
    case X21:
    default:
        ifr->ifr_settings.type = IF_IFACE_X21;
        break;
    }
    if (ifr->ifr_settings.size == 0)
    {
        return 0;
    }
    if (ifr->ifr_settings.size < sizeof(sync))
    {
        return -ENOMEM;
    }
    i = port->index;
    sync.clock_rate = FST_RDL(card, portConfig[i].lineSpeed);
    sync.clock_type = FST_RDB(card, portConfig[i].internalClock) == INTCLK ? CLOCK_INT : CLOCK_EXT;
    sync.loopback = 0;
    if (copy_to_user(ifr->ifr_settings.ifs_ifsu.sync, &sync, sizeof(sync)))
    {
        return -EFAULT;
    }
    ifr->ifr_settings.size = sizeof(sync);
    return 0;
}