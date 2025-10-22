static int rndis_filter_query_device(struct rndis_device *dev, u32 oid, void *result, u32 *result_size)
{
    struct rndis_request *request;
    u32 inresult_size = *result_size;
    struct rndis_query_request *query;
    struct rndis_query_complete *query_complete;
    int ret = 0;
    int t;
    if (!result)
    {
        return -EINVAL;
    }
    *result_size = 0;
    request = get_rndis_request(dev, RNDIS_MSG_QUERY, RNDIS_MESSAGE_SIZE(rndis_query_request));
    if (!request)
    {
        ret = -ENOMEM;
        cleanup
    }
    query = &request->request_msg.msg.query_req;
    query->oid = oid;
    query->info_buf_offset = sizeof(rndis_query_request);
    query->info_buflen = 0;
    query->dev_vc_handle = 0;
    if (oid == OID_GEN_RECEIVE_SCALE_CAPABILITIES)
    {
        struct ndis_recv_scale_cap *cap;
        request->request_msg.msg_len += sizeof(ndis_recv_scale_cap);
        query->info_buflen = sizeof(ndis_recv_scale_cap);
        cap = (ndis_recv_scale_cap *)((unsigned long)query + query->info_buf_offset);
        cap->hdr.type = NDIS_OBJECT_TYPE_RSS_CAPABILITIES;
        cap->hdr.rev = NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_2;
        cap->hdr.size = sizeof(ndis_recv_scale_cap);
    }
    ret = rndis_filter_send_request(dev, request);
    if (ret != 0)
    {
        cleanup
    }
    t = wait_for_completion_timeout(&request->wait_event, 5 * HZ);
    if (t == 0)
    {
        ret = -ETIMEDOUT;
        cleanup
    }
    query_complete = &request->response_msg.msg.query_complete;
    if (query_complete->info_buflen > inresult_size)
    {
        ret = -1;
        cleanup
    }
    memcpy(result, (void *)((unsigned long)query_complete + query_complete->info_buf_offset), query_complete->info_buflen);
    *result_size = query_complete->info_buflen;
    cleanup if (request) { put_rndis_request(dev, request); }
    return ret;
}