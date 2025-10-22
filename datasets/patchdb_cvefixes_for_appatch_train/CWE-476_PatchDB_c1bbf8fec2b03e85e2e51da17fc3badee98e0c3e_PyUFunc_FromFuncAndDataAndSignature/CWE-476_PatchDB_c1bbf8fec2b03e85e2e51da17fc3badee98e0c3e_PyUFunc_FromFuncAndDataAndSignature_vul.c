NPY_NO_EXPORT PyObject *PyUFunc_FromFuncAndDataAndSignature(PyUFuncGenericFunction *func, void **data, char *types, int ntypes, int nin, int nout, int identity, char *name, char *doc, int check_return, const char *signature)
{
    PyUFuncObject *ufunc;
    ufunc = PyArray_malloc(sizeof(PyUFuncObject));
    if (ufunc == NULL)
    {
        return NULL;
    }
    PyObject_Init((PyObject *)ufunc, &PyUFunc_Type);
    ufunc->nin = nin;
    ufunc->nout = nout;
    ufunc->nargs = nin + nout;
    ufunc->identity = identity;
    ufunc->functions = func;
    ufunc->data = data;
    ufunc->types = types;
    ufunc->ntypes = ntypes;
    ufunc->check_return = check_return;
    ufunc->ptr = NULL;
    ufunc->obj = NULL;
    ufunc->userloops = NULL;
    ufunc->type_resolver = &PyUFunc_DefaultTypeResolver;
    ufunc->legacy_inner_loop_selector = &PyUFunc_DefaultLegacyInnerLoopSelector;
    ufunc->inner_loop_selector = NULL;
    ufunc->masked_inner_loop_selector = &PyUFunc_DefaultMaskedInnerLoopSelector;
    if (name == NULL)
    {
        ufunc->name = "?";
    }
    else
    {
        ufunc->name = name;
    }
    ufunc->doc = doc;
    ufunc->op_flags = PyArray_malloc(sizeof(npy_uint32) * ufunc->nargs);
    memset(ufunc->op_flags, 0, sizeof(npy_uint32) * ufunc->nargs);
    ufunc->iter_flags = 0;
    ufunc->core_enabled = 0;
    ufunc->core_num_dim_ix = 0;
    ufunc->core_num_dims = NULL;
    ufunc->core_dim_ixs = NULL;
    ufunc->core_offsets = NULL;
    ufunc->core_signature = NULL;
    if (signature != NULL)
    {
        if (_parse_signature(ufunc, signature) != 0)
        {
            Py_DECREF(ufunc);
            return NULL;
        }
    }
    return (PyObject *)ufunc;
}