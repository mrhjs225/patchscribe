static int hpsa_get_pdisk_of_ioaccel2(struct ctlr_info *h, struct CommandList *ioaccel2_cmd_to_abort, unsigned char *scsi3addr)
{
    struct ReportExtendedLUNdata *physicals = NULL;
    int responsesize = 24;
    int extended = 2;
    int reportsize = sizeof(*physicals) + HPSA_MAX_PHYS_LUN * responsesize;
    u32 nphysicals = 0;
    int found = 0;
    u32 find;
    int i;
    struct scsi_cmnd *scmd;
    struct hpsa_scsi_dev_t *d;
    struct io_accel2_cmd *c2a;
    u32 it_nexus;
    u32 scsi_nexus;
    if (ioaccel2_cmd_to_abort->cmd_type != CMD_IOACCEL2)
    {
        return 0;
    }
    c2a = &h->ioaccel2_cmd_pool[ioaccel2_cmd_to_abort->cmdindex];
    if (c2a == NULL)
    {
        return 0;
    }
    scmd = (scsi_cmnd *)ioaccel2_cmd_to_abort->scsi_cmd;
    if (scmd == NULL)
    {
        return 0;
    }
    d = scmd->device->hostdata;
    if (d == NULL)
    {
        return 0;
    }
    it_nexus = cpu_to_le32((u32)d->ioaccel_handle);
    scsi_nexus = cpu_to_le32((u32)c2a->scsi_nexus);
    find = c2a->scsi_nexus;
    if (h->raid_offload_debug > 0)
    {
        dev_info(&h->pdev->dev, "%s: scsi_nexus:0x%08x device id: 0x%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n", __func__, scsi_nexus, d->device_id[0], d->device_id[1], d->device_id[2], d->device_id[3], d->device_id[4], d->device_id[5], d->device_id[6], d->device_id[7], d->device_id[8], d->device_id[9], d->device_id[10], d->device_id[11], d->device_id[12], d->device_id[13], d->device_id[14], d->device_id[15]);
    }
    physicals = kzalloc(reportsize, GFP_KERNEL);
    if (hpsa_scsi_do_report_phys_luns(h, (ReportLUNdata *)physicals, reportsize, extended))
    {
        dev_err(&h->pdev->dev, "Can't lookup %s device handle: report physical LUNs failed.\n", "HP SSD Smart Path");
        kfree(physicals);
        return 0;
    }
    nphysicals = be32_to_cpu(*((__be32 *)physicals->LUNListLength)) / responsesize;
    for (i = 0; i < nphysicals; i++)
    {
        if (memcmp(&((ReportExtendedLUNdata *)physicals)->LUN[i][20], &find, 4) != 0)
        {
            continue;
        }
        found = 1;
        memcpy(scsi3addr, &((ReportExtendedLUNdata *)physicals)->LUN[i][0], 8);
        if (h->raid_offload_debug > 0)
        {
            dev_info(&h->pdev->dev, "%s: Searched h=0x%08x, Found h=0x%08x, scsiaddr 0x%02x%02x%02x%02x%02x%02x%02x%02x\n", __func__, find, ((ReportExtendedLUNdata *)physicals)->LUN[i][20], scsi3addr[0], scsi3addr[1], scsi3addr[2], scsi3addr[3], scsi3addr[4], scsi3addr[5], scsi3addr[6], scsi3addr[7]);
        }
        break;
    }
    kfree(physicals);
    if (found)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}