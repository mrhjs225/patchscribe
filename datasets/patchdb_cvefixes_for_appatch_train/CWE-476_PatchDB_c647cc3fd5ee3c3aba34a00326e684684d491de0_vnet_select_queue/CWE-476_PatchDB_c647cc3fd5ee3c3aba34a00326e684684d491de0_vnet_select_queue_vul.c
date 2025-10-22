static u16 vnet_select_queue(struct net_device *dev, struct sk_buff *skb, void *accel_priv, select_queue_fallback_t fallback)
{
    struct vnet *vp = netdev_priv(dev);
    struct vnet_port *port = __tx_port_find(vp, skb);
    return port->q_index;
}