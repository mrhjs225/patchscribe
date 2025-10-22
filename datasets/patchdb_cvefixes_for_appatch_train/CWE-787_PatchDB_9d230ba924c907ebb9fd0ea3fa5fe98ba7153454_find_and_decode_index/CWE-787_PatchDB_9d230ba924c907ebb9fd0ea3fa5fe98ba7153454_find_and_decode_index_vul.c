static int find_and_decode_index(NUTContext *nut)
{
    AVFormatContext *s = nut->avf;
    AVIOContext *bc = s->pb;
    uint64_t tmp, end;
    int i, j, syncpoint_count;
    int64_t filesize = avio_size(bc);
    int64_t *syncpoints;
    int8_t *has_keyframe;
    int ret = -1;
    avio_seek(bc, filesize - 12, SEEK_SET);
    avio_seek(bc, filesize - avio_rb64(bc), SEEK_SET);
    if (avio_rb64(bc) != INDEX_STARTCODE)
    {
        av_log(s, AV_LOG_ERROR, "no index at the end\n");
        return -1;
    }
    end = get_packetheader(nut, bc, 1, INDEX_STARTCODE);
    end += avio_tell(bc);
    ffio_read_varlen(bc);
    GET_V(, 8 0)
    syncpoints = av_malloc(sizeof(int64_t) * syncpoint_count);
    has_keyframe = av_malloc(sizeof(int8_t) * (syncpoint_count + 1));
    for (i = 0; i < syncpoint_count; i++)
    {
        syncpoints[i] = ffio_read_varlen(bc);
        if (syncpoints[i] <= 0)
        {
            fail
        }
        if (i)
        {
            syncpoints[i] += syncpoints[i - 1];
        }
    }
    for (i = 0; i < s->nb_streams; i++)
    {
        int64_t last_pts = -1;
        for (j = 0; j < syncpoint_count;)
        {
            uint64_t x = ffio_read_varlen(bc);
            int type = x & 1;
            int n = j;
            x >>= 1;
            if (type)
            {
                int flag = x & 1;
                x >>= 1;
                if (n + x >= syncpoint_count + 1)
                {
                    av_log(s, AV_LOG_ERROR, "index overflow A\n");
                    fail
                }
                while (x--)
                {
                    has_keyframe[n++] = flag;
                }
                has_keyframe[n++] = !flag;
            }
            else
            {
                while (x != 1)
                {
                    if (n >= syncpoint_count + 1)
                    {
                        av_log(s, AV_LOG_ERROR, "index overflow B\n");
                        fail
                    }
                    has_keyframe[n++] = x & 1;
                    x >>= 1;
                }
            }
            if (has_keyframe[0])
            {
                av_log(s, AV_LOG_ERROR, "keyframe before first syncpoint in index\n");
                fail
            }
            av_assert0(n <= syncpoint_count + 1);
            for (; j < n && j < syncpoint_count; j++)
            {
                if (has_keyframe[j])
                {
                    uint64_t B, A = ffio_read_varlen(bc);
                    if (!A)
                    {
                        A = ffio_read_varlen(bc);
                        B = ffio_read_varlen(bc);
                    }
                    else
                    {
                        B = 0;
                    }
                    av_add_index_entry(s->streams[i], 16 * syncpoints[j - 1], last_pts + A, 0, 0, AVINDEX_KEYFRAME);
                    last_pts += A + B;
                }
            }
        }
    }
    if (skip_reserved(bc, end) || ffio_get_checksum(bc))
    {
        av_log(s, AV_LOG_ERROR, "index checksum mismatch\n");
        fail
    }
    ret = 0;
    fail av_free(syncpoints);
    av_free(has_keyframe);
    return ret;
}