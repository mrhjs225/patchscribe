ssize_t o_stream_send(struct ostream *stream, const void *data, size_t size)
{
    struct _ostream *_stream = stream->real_stream;
    if (stream->closed)
    {
        return -1;
    }
    if (size == 0)
    {
        return 0;
    }
    return _stream->send(_stream, data, size);
}