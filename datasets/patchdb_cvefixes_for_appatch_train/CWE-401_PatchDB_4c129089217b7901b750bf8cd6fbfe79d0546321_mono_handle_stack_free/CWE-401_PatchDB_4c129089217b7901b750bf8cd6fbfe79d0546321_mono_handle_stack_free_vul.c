void mono_handle_stack_free(HandleStack *stack)
{
    if (!stack)
    {
        return;
    }
    HandleChunk *c = stack->bottom;
    while (c)
    {
        HandleChunk *next = c->next;
        g_free(c);
        c = next;
    }
    g_free(c);
}