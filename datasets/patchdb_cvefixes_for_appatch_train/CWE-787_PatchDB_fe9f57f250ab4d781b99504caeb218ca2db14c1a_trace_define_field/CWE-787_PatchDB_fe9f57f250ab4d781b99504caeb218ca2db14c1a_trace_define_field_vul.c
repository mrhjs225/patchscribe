int trace_define_field(struct ftrace_event_call *call, char *type, char *name, int offset, int size)
{
    struct ftrace_event_field *field;
    field = kmalloc(sizeof(*field), GFP_KERNEL);
    if (!field)
    {
        err
    }
    field->name = kstrdup(name, GFP_KERNEL);
    if (!field->name)
    {
        err
    }
    field->type = kstrdup(type, GFP_KERNEL);
    if (!field->type)
    {
        err
    }
    field->offset = offset;
    field->size = size;
    list_add(&field->link, &call->fields);
    return 0;
    err if (field)
    {
        kfree(field->name);
        kfree(field->type);
    }
    kfree(field);
    return -ENOMEM;
}