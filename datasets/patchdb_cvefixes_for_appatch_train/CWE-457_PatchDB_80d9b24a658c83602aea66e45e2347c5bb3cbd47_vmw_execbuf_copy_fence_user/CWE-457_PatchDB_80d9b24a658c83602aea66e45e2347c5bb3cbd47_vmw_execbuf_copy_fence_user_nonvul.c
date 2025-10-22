void vmw_execbuf_copy_fence_user(struct vmw_private *dev_priv, struct vmw_fpriv *vmw_fp, int ret, struct drm_vmw_fence_rep __user *user_fence_rep, struct vmw_fence_obj *fence, uint32_t fence_handle)
{
    struct drm_vmw_fence_rep fence_rep;
    if (user_fence_rep == NULL)
    {
        return;
    }
    memset(&fence_rep, 0, sizeof(fence_rep));
    fence_rep.error = ret;
    if (ret == 0)
    {
        BUG_ON(fence == NULL);
        fence_rep.handle = fence_handle;
        fence_rep.seqno = fence->seqno;
        vmw_update_seqno(dev_priv, &dev_priv->fifo);
        fence_rep.passed_seqno = dev_priv->last_read_seqno;
    }
    ret = copy_to_user(user_fence_rep, &fence_rep, sizeof(fence_rep));
    if (unlikely(ret != 0) && (fence_rep.error == 0))
    {
        ttm_ref_object_base_unref(vmw_fp->tfile, fence_handle, TTM_REF_USAGE);
        DRM_ERROR("Fence copy error. Syncing.\n");
        (void)vmw_fence_obj_wait(fence, fence->signal_mask, false, false, VMW_FENCE_WAIT_TIMEOUT);
    }
}