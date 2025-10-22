static int cy_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{
    struct cyclades_port *info = tty->driver_data;
    struct cyclades_icount cnow;
    int ret_val = 0;
    unsigned long flags;
    void __user *argp = (void __user *)arg;
    if (serial_paranoia_check(info, tty->name, "cy_ioctl"))
    {
        return -ENODEV;
    }
    printk(KERN_DEBUG "cyc:cy_ioctl ttyC%d, cmd = %x arg = %lx\n", info->line, cmd, arg);
    switch (cmd)
    {
    case CYGETMON:
        if (copy_to_user(argp, &info->mon, sizeof(info->mon)))
        {
            ret_val = -EFAULT;
            break;
        }
        memset(&info->mon, 0, sizeof(info->mon));
        break;
    case CYGETTHRESH:
        ret_val = get_threshold(info, argp);
        break;
    case CYSETTHRESH:
        ret_val = set_threshold(info, arg);
        break;
    case CYGETDEFTHRESH:
        ret_val = put_user(info->default_threshold, (unsigned long __user *)argp);
        break;
    case CYSETDEFTHRESH:
        info->default_threshold = arg & 0x0f;
        break;
    case CYGETTIMEOUT:
        ret_val = get_timeout(info, argp);
        break;
    case CYSETTIMEOUT:
        ret_val = set_timeout(info, arg);
        break;
    case CYGETDEFTIMEOUT:
        ret_val = put_user(info->default_timeout, (unsigned long __user *)argp);
        break;
    case CYSETDEFTIMEOUT:
        info->default_timeout = arg & 0xff;
        break;
    case CYSETRFLOW:
        info->rflow = (int)arg;
        break;
    case CYGETRFLOW:
        ret_val = info->rflow;
        break;
    case CYSETRTSDTR_INV:
        info->rtsdtr_inv = (int)arg;
        break;
    case CYGETRTSDTR_INV:
        ret_val = info->rtsdtr_inv;
        break;
    case CYGETCD1400VER:
        ret_val = info->chip_rev;
        break;
    case CYZSETPOLLCYCLE:
        if (arg > LONG_MAX / HZ)
        {
            return -ENODEV;
        }
        cyz_polling_cycle = (arg * HZ) / 1000;
        break;
    case CYZGETPOLLCYCLE:
        ret_val = (cyz_polling_cycle * 1000) / HZ;
        break;
    case CYSETWAIT:
        info->port.closing_wait = (unsigned short)arg * HZ / 100;
        break;
    case CYGETWAIT:
        ret_val = info->port.closing_wait / (HZ / 100);
        break;
    case TIOCGSERIAL:
        ret_val = cy_get_serial_info(info, argp);
        break;
    case TIOCSSERIAL:
        ret_val = cy_set_serial_info(info, tty, argp);
        break;
    case TIOCSERGETLSR:
        ret_val = get_lsr_info(info, argp);
        break;
    case TIOCMIWAIT:
        spin_lock_irqsave(&info->card->card_lock, flags);
        cnow = info->icount;
        spin_unlock_irqrestore(&info->card->card_lock, flags);
        ret_val = wait_event_interruptible(info->port.delta_msr_wait, cy_cflags_changed(info, arg, &cnow));
        break;
    default:
        ret_val = -ENOIOCTLCMD;
    }
    printk(KERN_DEBUG "cyc:cy_ioctl done\n");
    return ret_val;
}