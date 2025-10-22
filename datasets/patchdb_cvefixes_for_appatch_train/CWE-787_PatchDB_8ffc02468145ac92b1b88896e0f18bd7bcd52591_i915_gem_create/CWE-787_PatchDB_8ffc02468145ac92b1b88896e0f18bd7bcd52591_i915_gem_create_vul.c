static int i915_gem_create(struct drm_file *file, struct drm_device *dev, uint64_t size, uint32_t *handle_p)
{
    struct drm_i915_gem_object *obj;
    int ret;
    u32 handle;
    size = roundup(size, PAGE_SIZE);
    obj = i915_gem_alloc_object(dev, size);
    if (obj == NULL)
    {
        return -ENOMEM;
    }
    ret = drm_gem_handle_create(file, &obj->base, &handle);
    if (ret)
    {
        drm_gem_object_release(&obj->base);
        i915_gem_info_remove_obj(dev->dev_private, obj->base.size);
        kfree(obj);
        return ret;
    }
    drm_gem_object_unreference(&obj->base);
    trace_i915_gem_object_create(obj);
    *handle_p = handle;
    return 0;
}