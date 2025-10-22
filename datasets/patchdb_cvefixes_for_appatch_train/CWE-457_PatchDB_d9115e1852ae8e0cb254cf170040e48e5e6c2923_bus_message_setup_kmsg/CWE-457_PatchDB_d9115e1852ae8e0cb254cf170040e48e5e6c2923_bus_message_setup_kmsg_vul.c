static int bus_message_setup_kmsg(sd_bus_message *m)
{
    struct kdbus_msg_data *d;
    bool well_known;
    uint64_t unique;
    size_t sz, dl;
    int r;
    assert(m);
    assert(m->sealed);
    if (m->kdbus)
    {
        return 0;
    }
    if (m->destination)
    {
        r = parse_unique_name(m->destination, &unique);
        if (r < 0)
        {
            return r;
        }
        well_known = r == 0;
    }
    else
    {
        well_known = false;
    }
    sz = offsetof(kdbus_msg, data);
    sz += 4 * ALIGN8(offsetof(kdbus_msg_data, vec) + sizeof(kdbus_vec));
    if (well_known)
    {
        dl = strlen(m->destination);
        sz += ALIGN8(offsetof(kdbus_msg, data) + dl + 1);
    }
    m->kdbus = aligned_alloc(8, sz);
    if (!m->kdbus)
    {
        return -ENOMEM;
    }
    m->kdbus->flags = ((m->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED) ? 0 : KDBUS_MSG_FLAGS_EXPECT_REPLY) | ((m->header->flags & SD_BUS_MESSAGE_NO_AUTO_START) ? KDBUS_MSG_FLAGS_NO_AUTO_START : 0);
    m->kdbus->dst_id = well_known ? 0 : m->destination ? unique : (uint64_t)-1;
    m->kdbus->payload_type = KDBUS_PAYLOAD_DBUS1;
    m->kdbus->cookie = m->header->serial;
    m->kdbus->timeout_ns = m->timeout * NSEC_PER_USEC;
    d = m->kdbus->data;
    if (well_known)
    {
        append_destination(&d, m->destination, dl);
    }
    append_payload_vec(&d, m->header, sizeof(*m->header));
    if (m->fields)
    {
        append_payload_vec(&d, m->fields, m->header->fields_size);
        if (m->header->fields_size % 8 != 0)
        {
            static const uint8_t padding[7]{};
            ;
            append_payload_vec(&d, padding, 8 - (m->header->fields_size % 8));
        }
    }
    if (m->body)
    {
        append_payload_vec(&d, m->body, m->header->body_size);
    }
    m->kdbus->size = (uint8_t *)d - (uint8_t *)m->kdbus;
    assert(m->kdbus->size <= sz);
    m->free_kdbus = true;
    return 0;
}