static PyObject *ufunc_frompyfunc(PyObject *NPY_UNUSED(dummy), PyObject *args, PyObject *NPY_UNUSED(kwds))
{
    PyObject *function, *pyname = NULL;
    int nin, nout, i;
    PyUFunc_PyFuncData *fdata;
    PyUFuncObject *self;
    char *fname, *str;
    Py_ssize_t fname_len = -1;
    int offset[2];
    if (!PyArg_ParseTuple(args, "Oii", &function, &nin, &nout))
    {
        return NULL;
    }
    if (!PyCallable_Check(function))
    {
        PyErr_SetString(PyExc_TypeError, "function must be callable");
        return NULL;
    }
    self = PyArray_malloc(sizeof(PyUFuncObject));
    if (self == NULL)
    {
        return NULL;
    }
    PyObject_Init((PyObject *)self, &PyUFunc_Type);
    self->userloops = NULL;
    self->nin = nin;
    self->nout = nout;
    self->nargs = nin + nout;
    self->identity = PyUFunc_None;
    self->functions = pyfunc_functions;
    self->ntypes = 1;
    self->check_return = 0;
    self->core_enabled = 0;
    self->core_num_dim_ix = 0;
    self->core_num_dims = NULL;
    self->core_dim_ixs = NULL;
    self->core_offsets = NULL;
    self->core_signature = NULL;
    self->op_flags = PyArray_malloc(sizeof(npy_uint32) * self->nargs);
    memset(self->op_flags, 0, sizeof(npy_uint32) * self->nargs);
    self->iter_flags = 0;
    self->type_resolver = &object_ufunc_type_resolver;
    self->legacy_inner_loop_selector = &object_ufunc_loop_selector;
    pyname = PyObject_GetAttrString(function, "__name__");
    if (pyname)
    {
        (void)PyString_AsStringAndSize(pyname, &fname, &fname_len);
    }
    if (PyErr_Occurred())
    {
        fname = "?";
        fname_len = 1;
        PyErr_Clear();
    }
    offset[0] = sizeof(PyUFunc_PyFuncData);
    i = (sizeof(PyUFunc_PyFuncData) % sizeof(void *));
    if (i)
    {
        offset[0] += (sizeof(void *) - i);
    }
    offset[1] = self->nargs;
    i = (self->nargs % sizeof(void *));
    if (i)
    {
        offset[1] += (sizeof(void *) - i);
    }
    self->ptr = PyArray_malloc(offset[0] + offset[1] + sizeof(void *) + (fname_len + 14));
    if (self->ptr == NULL)
    {
        Py_XDECREF(pyname);
        return PyErr_NoMemory();
    }
    Py_INCREF(function);
    self->obj = function;
    fdata = (PyUFunc_PyFuncData *)(self->ptr);
    fdata->nin = nin;
    fdata->nout = nout;
    fdata->callable = function;
    self->data = (void **)(((char *)self->ptr) + offset[0]);
    self->data[0] = (void *)fdata;
    self->types = (char *)self->data + sizeof(void *);
    for (i = 0; i < self->nargs; i++)
    {
        self->types[i] = NPY_OBJECT;
    }
    str = self->types + offset[1];
    memcpy(str, fname, fname_len);
    memcpy(str + fname_len, " (vectorized)", 14);
    self->name = str;
    Py_XDECREF(pyname);
    self->doc = "dynamic ufunc based on a python function";
    return (PyObject *)self;
}