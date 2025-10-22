static struct pending_cmd *mgmt_pending_add(struct sock *sk, u16 opcode, struct hci_dev *hdev, void *data, u16 len)
{
    struct pending_cmd *cmd;
    cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
    if (!cmd)
    {
        return NULL;
    }
    cmd->opcode = opcode;
    cmd->index = hdev->id;
    cmd->param = kmalloc(len, GFP_KERNEL);
    if (!cmd->param)
    {
        kfree(cmd);
        return NULL;
    }
    if (data)
    {
        memcpy(cmd->param, data, len);
    }
    cmd->sk = sk;
    sock_hold(sk);
    list_add(&cmd->list, &hdev->mgmt_pending);
    return cmd;
}