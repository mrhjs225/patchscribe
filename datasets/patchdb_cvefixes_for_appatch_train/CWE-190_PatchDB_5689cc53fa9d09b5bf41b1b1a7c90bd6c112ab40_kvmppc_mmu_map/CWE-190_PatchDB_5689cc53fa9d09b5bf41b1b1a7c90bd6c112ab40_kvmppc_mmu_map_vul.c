void kvmppc_mmu_map(struct kvm_vcpu *vcpu, u64 gvaddr, gpa_t gpaddr, unsigned int gtlb_index)
{
    struct kvmppc_44x_tlbe stlbe;
    struct kvmppc_vcpu_44x *vcpu_44x = to_44x(vcpu);
    struct kvmppc_44x_tlbe *gtlbe = &vcpu_44x->guest_tlb[gtlb_index];
    struct kvmppc_44x_shadow_ref *ref;
    struct page *new_page;
    hpa_t hpaddr;
    gfn_t gfn;
    u32 asid = gtlbe->tid;
    u32 flags = gtlbe->word2;
    u32 max_bytes = get_tlb_bytes(gtlbe);
    unsigned int victim;
    local_irq_disable();
    victim = ++tlb_44x_index;
    if (victim > tlb_44x_hwater)
    {
        victim = 0;
    }
    tlb_44x_index = victim;
    local_irq_enable();
    gfn = gpaddr >> PAGE_SHIFT;
    new_page = gfn_to_page(vcpu->kvm, gfn);
    if (is_error_page(new_page))
    {
        printk(KERN_ERR "Couldn't get guest page for gfn %lx!\n", gfn);
        kvm_release_page_clean(new_page);
        return;
    }
    hpaddr = page_to_phys(new_page);
    kvmppc_44x_shadow_release(vcpu_44x, victim);
    stlbe.word0 = PPC44x_TLB_VALID | PPC44x_TLB_TS;
    if (max_bytes >= PAGE_SIZE)
    {
        stlbe.word0 |= (gvaddr & PAGE_MASK) | PPC44x_TLBE_SIZE;
    }
    else
    {
        stlbe.word0 |= (gvaddr & PAGE_MASK_4K) | PPC44x_TLB_4K;
        hpaddr |= gpaddr & (PAGE_MASK ^ PAGE_MASK_4K);
    }
    stlbe.word1 = (hpaddr & 0xfffffc00) | ((hpaddr >> 32) & 0xf);
    stlbe.word2 = kvmppc_44x_tlb_shadow_attrib(flags, vcpu->arch.msr & MSR_PR);
    stlbe.tid = !(asid & 0xff);
    ref = &vcpu_44x->shadow_refs[victim];
    ref->page = new_page;
    ref->gtlb_index = gtlb_index;
    ref->writeable = !!(stlbe.word2 & PPC44x_TLB_UW);
    ref->tid = stlbe.tid;
    kvmppc_44x_tlbe_set_modified(vcpu_44x, victim);
    kvmppc_44x_tlbwe(victim, &stlbe);
    trace_kvm_stlb_write(victim, stlbe.tid, stlbe.word0, stlbe.word1, stlbe.word2);
}