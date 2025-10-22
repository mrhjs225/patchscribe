void cib_ha_peer_callback(HA_Message *msg, void *private_data)
{
    xmlNode *xml = convert_ha_message(NULL, msg, __FUNCTION__);
    cib_peer_callback(xml, private_data);
}