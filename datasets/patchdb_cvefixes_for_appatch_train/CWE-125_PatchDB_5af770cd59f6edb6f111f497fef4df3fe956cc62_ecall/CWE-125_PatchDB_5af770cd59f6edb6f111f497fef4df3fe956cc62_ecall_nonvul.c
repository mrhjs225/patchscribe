static void ecall(mrb_state *mrb, int i)
{
    struct RProc *p;
    mrb_callinfo *ci;
    mrb_value *self = mrb->c->stack;
    struct RObject *exc;
    if (i < 0)
    {
        return;
    }
    p = mrb->c->ensure[i];
    if (!p)
    {
        return;
    }
    if (mrb->c->ci->eidx > i)
    {
        mrb->c->ci->eidx = i;
    }
    ci = cipush(mrb);
    ci->stackent = mrb->c->stack;
    ci->mid = ci[-1].mid;
    ci->acc = CI_ACC_SKIP;
    ci->argc = 0;
    ci->proc = p;
    ci->nregs = p->body.irep->nregs;
    ci->target_class = p->target_class;
    mrb->c->stack = mrb->c->stack + ci[-1].nregs;
    exc = mrb->exc;
    mrb->exc = 0;
    mrb_run(mrb, p, *self);
    mrb->c->ensure[i] = NULL;
    if (!mrb->exc)
    {
        mrb->exc = exc;
    }
}