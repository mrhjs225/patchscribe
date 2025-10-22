static int start_afu(struct cxlflash_cfg *cfg)
{
    struct afu *afu = cfg->afu;
    struct afu_cmd *cmd;
    int i = 0;
    int rc = 0;
    for (i = 0; i < CXLFLASH_NUM_CMDS; i++)
    {
        cmd = &afu->cmd[i];
        init_completion(&cmd->cevent);
        spin_lock_init(&cmd->slock);
        cmd->parent = afu;
    }
    init_pcr(cfg);
    afu->hrrq_start = &afu->rrq_entry[0];
    afu->hrrq_end = &afu->rrq_entry[NUM_RRQ_ENTRY - 1];
    afu->hrrq_curr = afu->hrrq_start;
    afu->toggle = 1;
    rc = init_global(cfg);
    pr_debug("%s: returning rc=%d\n", __func__, rc);
    return rc;
}