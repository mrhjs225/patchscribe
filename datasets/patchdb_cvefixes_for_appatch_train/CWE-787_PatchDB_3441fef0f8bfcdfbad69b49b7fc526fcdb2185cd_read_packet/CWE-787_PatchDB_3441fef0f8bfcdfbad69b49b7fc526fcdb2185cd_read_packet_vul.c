static int read_packet(AVFormatContext *s, AVPacket *pkt)
{
    AVCodecContext *codec = s->streams[0]->codec;
    BRSTMDemuxContext *b = s->priv_data;
    uint32_t samples, size, skip = 0;
    int ret, i;
    if (avio_feof(s->pb))
    {
        return AVERROR_EOF;
    }
    b->current_block++;
    if (b->current_block == b->block_count)
    {
        size = b->last_block_used_bytes;
        samples = b->last_block_samples;
        skip = b->last_block_size - b->last_block_used_bytes;
        if (samples < size * 14 / 8)
        {
            uint32_t adjusted_size = samples / 14 * 8;
            if (samples % 14)
            {
                adjusted_size += (samples % 14 + 1) / 2 + 1;
            }
            skip += size - adjusted_size;
            size = adjusted_size;
        }
    }
    if (b->current_block < b->block_count)
    {
        size = b->block_size;
        samples = b->samples_per_block;
    }
    else
    {
        return AVERROR_EOF;
    }
    if (codec->codec_id == AV_CODEC_ID_ADPCM_THP || codec->codec_id == AV_CODEC_ID_ADPCM_THP_LE)
    {
        uint8_t *dst;
        if (av_new_packet(pkt, 8 + (32 + 4 + size) * codec->channels) < 0)
        {
            return AVERROR(ENOMEM);
        }
        dst = pkt->data;
        if (codec->codec_id == AV_CODEC_ID_ADPCM_THP_LE)
        {
            bytestream_put_le32(&dst, size * codec->channels);
            bytestream_put_le32(&dst, samples);
        }
        else
        {
            bytestream_put_be32(&dst, size * codec->channels);
            bytestream_put_be32(&dst, samples);
        }
        bytestream_put_buffer(&dst, b->table, 32 * codec->channels);
        bytestream_put_buffer(&dst, b->adpc + 4 * codec->channels * (b->current_block - 1), 4 * codec->channels);
        for (i = 0; i < codec->channels; i++)
        {
            ret = avio_read(s->pb, dst, size);
            dst += size;
            avio_skip(s->pb, skip);
            if (ret != size)
            {
                av_free_packet(pkt);
                break;
            }
        }
        pkt->duration = samples;
    }
    else
    {
        size *= codec->channels;
        ret = av_get_packet(s->pb, pkt, size);
    }
    pkt->stream_index = 0;
    if (ret != size)
    {
        ret = AVERROR(EIO);
    }
    return ret;
}