static int probe_common(struct virtio_device *vdev)
{
    int err, i;
    struct virtrng_info *vi = NULL;
    vi = kmalloc(sizeof(virtrng_info), GFP_KERNEL);
    vi->hwrng.name = kmalloc(40, GFP_KERNEL);
    init_completion(&vi->have_data);
    vi->hwrng.read = virtio_read;
    vi->hwrng.cleanup = virtio_cleanup;
    vi->hwrng.priv = (unsigned long)vi;
    vdev->priv = vi;
    vi->vq = virtio_find_single_vq(vdev, random_recv_done, "input");
    if (IS_ERR(vi->vq))
    {
        err = PTR_ERR(vi->vq);
        kfree(vi->hwrng.name);
        vi->vq = NULL;
        kfree(vi);
        vi = NULL;
        return err;
    }
    i = 0;
    {
        sprintf(vi->hwrng.name, "virtio_rng.%d", i++);
        err = hwrng_register(&vi->hwrng);
    }
    err == -EEXIST;
    if (err)
    {
        vdev->config->del_vqs(vdev);
        kfree(vi->hwrng.name);
        vi->vq = NULL;
        kfree(vi);
        vi = NULL;
        return err;
    }
    return 0;
}