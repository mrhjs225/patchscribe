NPY_NO_EXPORT PyObject *PyArray_FromString(char *data, npy_intp slen, PyArray_Descr *dtype, npy_intp num, char *sep)
{
    int itemsize;
    PyArrayObject *ret;
    Bool binary;
    if (dtype == NULL)
    {
        dtype = PyArray_DescrFromType(NPY_DEFAULT_TYPE);
        if (dtype == NULL)
        {
            return NULL;
        }
    }
    if (PyDataType_FLAGCHK(dtype, NPY_ITEM_IS_POINTER) || PyDataType_REFCHK(dtype))
    {
        PyErr_SetString(PyExc_ValueError, "Cannot create an object array from"
                                          " a string");
        Py_DECREF(dtype);
        return NULL;
    }
    itemsize = dtype->elsize;
    if (itemsize == 0)
    {
        PyErr_SetString(PyExc_ValueError, "zero-valued itemsize");
        Py_DECREF(dtype);
        return NULL;
    }
    binary = ((sep == NULL) || (strlen(sep) == 0));
    if (binary)
    {
        if (num < 0)
        {
            if (slen % itemsize != 0)
            {
                PyErr_SetString(PyExc_ValueError, "string size must be a "
                                                  "multiple of element size");
                Py_DECREF(dtype);
                return NULL;
            }
            num = slen / itemsize;
        }
        else
        {
            if (slen < num * itemsize)
            {
                PyErr_SetString(PyExc_ValueError, "string is smaller than "
                                                  "requested size");
                Py_DECREF(dtype);
                return NULL;
            }
        }
        ret = (PyArrayObject *)PyArray_NewFromDescr(&PyArray_Type, dtype, 1, &num, NULL, NULL, 0, NULL);
        if (ret == NULL)
        {
            return NULL;
        }
        memcpy(PyArray_DATA(ret), data, num * dtype->elsize);
    }
    else
    {
        size_t nread = 0;
        char *end;
        if (dtype->f->scanfunc == NULL)
        {
            PyErr_SetString(PyExc_ValueError, "don't know how to read "
                                              "character strings with that "
                                              "array type");
            Py_DECREF(dtype);
            return NULL;
        }
        if (slen < 0)
        {
            end = NULL;
        }
        else
        {
            end = data + slen;
        }
        ret = array_from_text(dtype, num, sep, &nread, data, (next_element)fromstr_next_element, (skip_separator)fromstr_skip_separator, end);
    }
    return (PyObject *)ret;
}