void qlcnic_set_multi(struct net_device *netdev)
{
    struct qlcnic_adapter *adapter = netdev_priv(netdev);
    struct netdev_hw_addr *ha;
    struct qlcnic_mac_list_s *cur;
    if (!test_bit(__QLCNIC_FW_ATTACHED, &adapter->state))
    {
        return;
    }
    if (qlcnic_sriov_vf_check(adapter))
    {
        if (!netdev_mc_empty(netdev))
        {
            netdev_for_each_mc_addr(, )
            {
                cur = kzalloc(sizeof(qlcnic_mac_list_s), GFP_ATOMIC);
                memcpy(cur->mac_addr, ha->addr, ETH_ALEN);
                list_add_tail(&cur->list, &adapter->vf_mc_list);
            }
        }
        qlcnic_sriov_vf_schedule_multi(adapter->netdev);
        return;
    }
    __qlcnic_set_multi(netdev);
}