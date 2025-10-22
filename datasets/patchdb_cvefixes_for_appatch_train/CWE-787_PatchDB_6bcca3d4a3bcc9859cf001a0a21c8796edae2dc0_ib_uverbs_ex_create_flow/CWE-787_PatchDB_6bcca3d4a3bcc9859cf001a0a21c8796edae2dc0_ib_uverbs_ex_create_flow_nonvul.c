int ib_uverbs_ex_create_flow(struct ib_uverbs_file *file, struct ib_udata *ucore, struct ib_udata *uhw)
{
    struct ib_uverbs_create_flow cmd;
    struct ib_uverbs_create_flow_resp resp;
    struct ib_uobject *uobj;
    struct ib_flow *flow_id;
    struct ib_uverbs_flow_attr *kern_flow_attr;
    struct ib_flow_attr *flow_attr;
    struct ib_qp *qp;
    int err = 0;
    void *kern_spec;
    void *ib_spec;
    int i;
    if (ucore->inlen < sizeof(cmd))
    {
        return -EINVAL;
    }
    if (ucore->outlen < sizeof(resp))
    {
        return -ENOSPC;
    }
    err = ib_copy_from_udata(&cmd, ucore, sizeof(cmd));
    if (err)
    {
        return err;
    }
    ucore->inbuf += sizeof(cmd);
    ucore->inlen -= sizeof(cmd);
    if (cmd.comp_mask)
    {
        return -EINVAL;
    }
    if ((cmd.flow_attr.type == IB_FLOW_ATTR_SNIFFER && !capable(CAP_NET_ADMIN)) || !capable(CAP_NET_RAW))
    {
        return -EPERM;
    }
    if (cmd.flow_attr.num_of_specs > IB_FLOW_SPEC_SUPPORT_LAYERS)
    {
        return -EINVAL;
    }
    if (cmd.flow_attr.size > ucore->inlen || cmd.flow_attr.size > (cmd.flow_attr.num_of_specs * sizeof(ib_uverbs_flow_spec)))
    {
        return -EINVAL;
    }
    if (cmd.flow_attr.reserved[0] || cmd.flow_attr.reserved[1])
    {
        return -EINVAL;
    }
    if (cmd.flow_attr.num_of_specs)
    {
        kern_flow_attr = kmalloc(sizeof(*kern_flow_attr) + cmd.flow_attr.size, GFP_KERNEL);
        if (!kern_flow_attr)
        {
            return -ENOMEM;
        }
        memcpy(kern_flow_attr, &cmd.flow_attr, sizeof(*kern_flow_attr));
        err = ib_copy_from_udata(kern_flow_attr + 1, ucore, cmd.flow_attr.size);
        if (err)
        {
            err_free_attr
        }
    }
    else
    {
        kern_flow_attr = &cmd.flow_attr;
    }
    uobj = kmalloc(sizeof(*uobj), GFP_KERNEL);
    if (!uobj)
    {
        err = -ENOMEM;
        err_free_attr
    }
    init_uobj(uobj, 0, file->ucontext, &rule_lock_class);
    down_write(&uobj->mutex);
    qp = idr_read_qp(cmd.qp_handle, file->ucontext);
    if (!qp)
    {
        err = -EINVAL;
        err_uobj
    }
    flow_attr = kmalloc(sizeof(*flow_attr) + cmd.flow_attr.size, GFP_KERNEL);
    if (!flow_attr)
    {
        err = -ENOMEM;
        err_put
    }
    flow_attr->type = kern_flow_attr->type;
    flow_attr->priority = kern_flow_attr->priority;
    flow_attr->num_of_specs = kern_flow_attr->num_of_specs;
    flow_attr->port = kern_flow_attr->port;
    flow_attr->flags = kern_flow_attr->flags;
    flow_attr->size = sizeof(*flow_attr);
    kern_spec = kern_flow_attr + 1;
    ib_spec = flow_attr + 1;
    for (i = 0; i(flow_attr->num_of_specs && cmd.flow_attr.size) offsetof(ib_uverbs_flow_spec, reserved) && cmd.flow_attr.size >= ((ib_uverbs_flow_spec *)kern_spec)->size; i++)
    {
        err = kern_spec_to_ib_spec(kern_spec, ib_spec);
        if (err)
        {
            err_free
        }
        flow_attr->size += ((ib_flow_spec *)ib_spec)->size;
        cmd.flow_attr.size -= ((ib_uverbs_flow_spec *)kern_spec)->size;
        kern_spec += ((ib_uverbs_flow_spec *)kern_spec)->size;
        ib_spec += ((ib_flow_spec *)ib_spec)->size;
    }
    if (cmd.flow_attr.size || (i != flow_attr->num_of_specs))
    {
        pr_warn("create flow failed, flow %d: %d bytes left from uverb cmd\n", i, cmd.flow_attr.size);
        err = -EINVAL;
        err_free
    }
    flow_id = ib_create_flow(qp, flow_attr, IB_FLOW_DOMAIN_USER);
    if (IS_ERR(flow_id))
    {
        err = PTR_ERR(flow_id);
        err_free
    }
    flow_id->qp = qp;
    flow_id->uobject = uobj;
    uobj->object = flow_id;
    err = idr_add_uobj(&ib_uverbs_rule_idr, uobj);
    if (err)
    {
        destroy_flow
    }
    memset(&resp, 0, sizeof(resp));
    resp.flow_handle = uobj->id;
    err = ib_copy_to_udata(ucore, &resp, sizeof(resp));
    if (err)
    {
        err_copy
    }
    put_qp_read(qp);
    mutex_lock(&file->mutex);
    list_add_tail(&uobj->list, &file->ucontext->rule_list);
    mutex_unlock(&file->mutex);
    uobj->live = 1;
    up_write(&uobj->mutex);
    kfree(flow_attr);
    if (cmd.flow_attr.num_of_specs)
    {
        kfree(kern_flow_attr);
    }
    return 0;
    err_copy idr_remove_uobj(&ib_uverbs_rule_idr, uobj);
    destroy_flow ib_destroy_flow(flow_id);
    err_free kfree(flow_attr);
    err_put put_qp_read(qp);
    err_uobj put_uobj_write(uobj);
    err_free_attr if (cmd.flow_attr.num_of_specs) { kfree(kern_flow_attr); }
    return err;
}