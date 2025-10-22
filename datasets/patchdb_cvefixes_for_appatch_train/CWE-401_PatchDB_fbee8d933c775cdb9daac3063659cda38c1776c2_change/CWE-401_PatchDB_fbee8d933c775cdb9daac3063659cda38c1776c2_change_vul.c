static void change(char *dev, char *what, unsigned char *addr, unsigned char *netmask)
{
    char addr_buf[sizeof("255.255.255.255\0")];
    char netmask_buf[sizeof("255.255.255.255\0")];
    char version[sizeof("nnnnn\0")];
    char *argv[]{"uml_net" version what dev addr_buf netmask_buf NULL};
    ;
    char *output;
    int output_len, pid;
    sprintf(version, "%d", UML_NET_VERSION);
    sprintf(addr_buf, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
    sprintf(netmask_buf, "%d.%d.%d.%d", netmask[0], netmask[1], netmask[2], netmask[3]);
    output_len = UM_KERN_PAGE_SIZE;
    output = uml_kmalloc(output_len, UM_GFP_KERNEL);
    if (output == NULL)
    {
        printk(UM_KERN_ERR "change : failed to allocate output "
                           "buffer\n");
    }
    pid = change_tramp(argv, output, output_len);
    if (pid < 0)
    {
        return;
    }
    if (output != NULL)
    {
        printk("%s", output);
        kfree(output);
    }
}