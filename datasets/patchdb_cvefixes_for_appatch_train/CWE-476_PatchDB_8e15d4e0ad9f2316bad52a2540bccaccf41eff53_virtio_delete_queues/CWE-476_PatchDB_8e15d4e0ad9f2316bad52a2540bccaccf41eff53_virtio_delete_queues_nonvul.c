void virtio_delete_queues(VirtIODevice *vdev)
{
    struct virtqueue *vq;
    unsigned i;
    if (vdev->info == NULL)
    {
        return;
    }
    for (i = 0; i < vdev->maxQueues; i++)
    {
        vq = vdev->info[i].vq;
        if (vq != NULL)
        {
            vdev->device->delete_queue(&vdev->info[i]);
            vdev->info[i].vq = NULL;
        }
    }
}