int drm_vblank_get(struct drm_device *dev, int crtc)
{
    struct drm_vblank_crtc *vblank = &dev->vblank[crtc];
    unsigned long irqflags;
    int ret = 0;
    if (WARN_ON(crtc >= dev->num_crtcs))
    {
        return -EINVAL;
    }
    spin_lock_irqsave(&dev->vbl_lock, irqflags);
    if (atomic_add_return(1, &vblank->refcount) == 1)
    {
        ret = drm_vblank_enable(dev, crtc);
    }
    else
    {
        if (!vblank->enabled)
        {
            atomic_dec(&vblank->refcount);
            ret = -EINVAL;
        }
    }
    spin_unlock_irqrestore(&dev->vbl_lock, irqflags);
    return ret;
}