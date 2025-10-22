static void v4l2_ctrl_del_event(struct v4l2_subscribed_event *sev)
{
    struct v4l2_ctrl *ctrl = v4l2_ctrl_find(sev->fh->ctrl_handler, sev->id);
    v4l2_ctrl_lock(ctrl);
    list_del(&sev->node);
    v4l2_ctrl_unlock(ctrl);
}