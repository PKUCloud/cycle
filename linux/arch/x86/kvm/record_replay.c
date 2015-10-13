#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/checkpoint_rollback.h>
#include <asm/vmx.h>

#include "mmu.h"

/* Definitions from mmu.c */
#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))

#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

static u64 __read_mostly shadow_mmio_mask;

static bool is_mmio_spte(u64 spte)
{
	return (spte & shadow_mmio_mask) == shadow_mmio_mask;
}

static int is_shadow_present_pte(u64 pte)
{
	return pte & PT_PRESENT_MASK && !is_mmio_spte(pte);
}

static int is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static int is_last_spte(u64 pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return 1;
	if (is_large_pte(pte))
		return 1;
	return 0;
}

struct rr_ops *rr_ops;

/* Synchronize all vcpus before enabling record and replay */
static int __rr_vcpu_sync(struct kvm_vcpu *vcpu,
			  int (*master_func)(struct kvm_vcpu *vcpu),
			  int (*slave_func)(struct kvm_vcpu *vcpu))
{
	int ret = 0;
	struct kvm *kvm = vcpu->kvm;
	struct rr_kvm_info *rr_kvm_info = &kvm->rr_info;
	int i;
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	bool is_master = false;

	if (atomic_inc_return(&rr_kvm_info->nr_sync_vcpus) == 1) {
		is_master = true;
	}

	if (is_master) {
		RR_DLOG(INIT, "vcpu=%d is the master", vcpu->vcpu_id);
		for (i = 0; i < online_vcpus; ++i) {
			if (kvm->vcpus[i] == vcpu)
				continue;
			RR_DLOG(INIT, "vcpu=%d kick vcpu=%d", vcpu->vcpu_id,
				kvm->vcpus[i]->vcpu_id);
			kvm_vcpu_kick(kvm->vcpus[i]);
		}
		RR_DLOG(INIT, "vcpu=%d wait for other vcpus to sync",
			vcpu->vcpu_id);
		while (atomic_read(&rr_kvm_info->nr_sync_vcpus) < online_vcpus) {
			msleep(1);
		}
		/* Do master things here */
		if (master_func)
			ret = master_func(vcpu);
	} else {
		RR_DLOG(INIT, "vcpu=%d is the slave", vcpu->vcpu_id);
		while (atomic_read(&rr_kvm_info->nr_sync_vcpus) < online_vcpus) {
			msleep(1);
		}
		/* Do slave things here */
		if (slave_func)
			ret = slave_func(vcpu);
	}
	atomic_inc(&rr_kvm_info->nr_fin_vcpus);
	while (atomic_read(&rr_kvm_info->nr_fin_vcpus) < online_vcpus) {
		msleep(1);
	}
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return ret;
}

/* Initialization for RR_ASYNC_PREEMPTION_EPT */
static int __rr_ape_init(struct kvm_vcpu *vcpu)
{
	/* MUST make rr_info.enabled true before separating page tables */
	vcpu->rr_info.enabled = true;
	vcpu->rr_info.timer_value = rr_ctrl.timer_value;

	/* Obsolete existing paging structures to separate page tables of
	 * different vcpus.
	 */
	vcpu->kvm->arch.mmu_valid_gen++;
	kvm_mmu_unload(vcpu);
	kvm_mmu_reload(vcpu);

	rr_ops->ape_vmx_setup(vcpu->rr_info.timer_value);

	RR_DLOG(INIT, "vcpu=%d enabled, preemption_timer=%lu, root_hpa=0x%llx",
		vcpu->vcpu_id, vcpu->rr_info.timer_value,
		vcpu->arch.mmu.root_hpa);
	return 0;
}

int rr_init(struct rr_ops *vmx_rr_ops)
{
	RR_ASSERT(!rr_ops);
	rr_ops = vmx_rr_ops;
	RR_DLOG(INIT, "rr_ops initialized");
	return 0;
}
EXPORT_SYMBOL_GPL(rr_init);

int rr_vcpu_info_init(struct rr_vcpu_info *rr_info)
{
	memset(rr_info, 0, sizeof(*rr_info));
	rr_info->enabled = false;
	rr_info->timer_value = RR_DEFAULT_PREEMTION_TIMER_VAL;
	rr_info->requests = 0;
	mutex_init(&rr_info->event_list_lock);
	INIT_LIST_HEAD(&rr_info->event_list);
	INIT_LIST_HEAD(&rr_info->cow_pages);
	rr_info->nr_cow_pages = 0;
	return 0;
}
EXPORT_SYMBOL_GPL(rr_vcpu_info_init);

int rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info)
{
	atomic_set(&rr_kvm_info->nr_sync_vcpus, 0);
	atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	return 0;
}
EXPORT_SYMBOL_GPL(rr_kvm_info_init);

int rr_vcpu_enable(struct kvm_vcpu *vcpu)
{
	int ret;

	RR_DLOG(INIT, "vcpu=%d start", vcpu->vcpu_id);
	ret = __rr_vcpu_sync(vcpu, __rr_ape_init, __rr_ape_init);
	if (!ret)
		rr_make_request(RR_REQ_CHECKPOINT, &vcpu->rr_info);
	else
		RR_DLOG(ERR, "vcpu=%d fail to __rr_vcpu_sync()", vcpu->vcpu_id);
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return ret;
}
EXPORT_SYMBOL_GPL(rr_vcpu_enable);

static void __rr_vcpu_clean_event_list(struct kvm_vcpu *vcpu)
{
	struct rr_event *e, *temp;

	list_for_each_entry_safe(e, temp, &(vcpu->rr_info.event_list), link) {
		list_del(&e->link);
		kfree(e);
	}
}

void rr_vcpu_checkpoint(struct kvm_vcpu *vcpu)
{
	RR_DLOG(GEN, "vcpu=%d", vcpu->vcpu_id);
	mutex_lock(&(vcpu->rr_info.event_list_lock));
	rr_do_vcpu_checkpoint(vcpu);
	__rr_vcpu_clean_event_list(vcpu);
	mutex_unlock(&(vcpu->rr_info.event_list_lock));
}
EXPORT_SYMBOL_GPL(rr_vcpu_checkpoint);

void rr_vcpu_rollback(struct kvm_vcpu *vcpu)
{
	RR_DLOG(GEN, "vcpu=%d", vcpu->vcpu_id);
	rr_do_vcpu_rollback(vcpu);
}
EXPORT_SYMBOL_GPL(rr_vcpu_rollback);

void rr_vcpu_commit_memory_again(struct kvm_vcpu *vcpu)
{
	RR_DLOG(GEN, "vcpu=%d NOT_IMPLEMENTED", vcpu->vcpu_id);
}
EXPORT_SYMBOL_GPL(rr_vcpu_commit_memory_again);

void rr_vcpu_post_check(struct kvm_vcpu *vcpu)
{
	RR_DLOG(GEN, "vcpu=%d NOT_IMPLEMENTED", vcpu->vcpu_id);
	rr_clear_request(RR_REQ_POST_CHECK, &vcpu->rr_info);
}
EXPORT_SYMBOL_GPL(rr_vcpu_post_check);

int rr_vcpu_check_chunk(struct kvm_vcpu *vcpu)
{
	RR_DLOG(GEN, "vcpu=%d NOT_IMPLEMENTED", vcpu->vcpu_id);
	return RR_CHUNK_SKIP;
}
EXPORT_SYMBOL_GPL(rr_vcpu_check_chunk);

/* Add event to rr_info.event_list */
void rr_vcpu_add_irq(struct kvm_vcpu *vcpu, int delivery_mode, int vector,
		     int level, int trig_mode, unsigned long *dest_map)
{
	struct rr_event *eve;

	eve = kmalloc(sizeof(*eve), GFP_KERNEL);
	RR_ASSERT(eve);
	eve->delivery_mode = delivery_mode;
	eve->vector = vector;
	eve->level = level;
	eve->trig_mode = trig_mode;
	eve->dest_map = dest_map;

	mutex_lock(&(vcpu->rr_info.event_list_lock));
	list_add(&eve->link, &(vcpu->rr_info.event_list));
	mutex_unlock(&(vcpu->rr_info.event_list_lock));
}
EXPORT_SYMBOL_GPL(rr_vcpu_add_irq);

int do_apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
		       int vector, int level, int trig_mode,
		       unsigned long *dest_map);

/* Reinject irq when rollback */
void rr_vcpu_reinject_irq(struct kvm_vcpu *vcpu)
{
	struct rr_event *e;

	mutex_lock(&(vcpu->rr_info.event_list_lock));
	list_for_each_entry(e, &(vcpu->rr_info.event_list), link) {
		do_apic_accept_irq(vcpu->arch.apic, e->delivery_mode, e->vector,
				   e->level, e->trig_mode, e->dest_map);
	}
	mutex_unlock(&(vcpu->rr_info.event_list_lock));
}
EXPORT_SYMBOL_GPL(rr_vcpu_reinject_irq);

static inline void __rr_spte_set_pfn(u64 *sptep, pfn_t pfn)
{
	u64 spte = *sptep;

	spte &= ~PT64_BASE_ADDR_MASK;
	spte |= (u64)pfn << PAGE_SHIFT;
	*sptep = spte;
}

/* Allocate a new page to replace the original public page and update the spte.
 * Record this original-private mapping as well.
 * Should flush TLB after calling this function.
 */
void rr_vcpu_memory_cow(struct kvm_vcpu *vcpu, u64 *sptep, gfn_t gfn, pfn_t pfn)
{
	void *new_page;
	struct rr_cow_page *cow_page;

	cow_page = kmalloc(sizeof(*cow_page), GFP_ATOMIC);
	if (!cow_page) {
		RR_DLOG(ERR, "error: vcpu=%d fail to kmalloc() for cow_page",
			vcpu->vcpu_id);
		return;
	}
	new_page = kmalloc(PAGE_SIZE, GFP_ATOMIC);
	if (!new_page) {
		RR_DLOG(ERR, "error: vcpu=%d fail to kmalloc() for new_page",
			vcpu->vcpu_id);
		kfree(cow_page);
		return;
	}

	cow_page->gfn = gfn;
	cow_page->orig_pfn = pfn;
	cow_page->priv_pfn = __pa(new_page) >> PAGE_SHIFT;
	cow_page->sptep = sptep;
	copy_page(new_page, pfn_to_kaddr(pfn));
	__rr_spte_set_pfn(sptep, cow_page->priv_pfn);
	list_add(&cow_page->link, &(vcpu->rr_info.cow_pages));
	vcpu->rr_info.nr_cow_pages++;
}

static void *__rr_gfn_to_kaddr_ept(struct kvm_vcpu *vcpu, gfn_t gfn, int write)
{
	int level = vcpu->arch.mmu.shadow_root_level;
	hpa_t addr = (u64)gfn << PAGE_SHIFT;
	hpa_t shadow_addr = vcpu->arch.mmu.root_hpa;
	unsigned index;
	u64 *sptep;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT(vcpu->arch.mmu.root_hpa != INVALID_PAGE);

	for (; level >= PT_PAGE_TABLE_LEVEL; --level) {
		index = SHADOW_PT_INDEX(addr, level);
		sptep = ((u64 *)__va(shadow_addr)) + index;

		if (!is_shadow_present_pte(*sptep)) {
			return NULL;
		}
		*sptep |= VMX_EPT_ACCESS_BIT;
		if (is_last_spte(*sptep, level)) {
			RR_ASSERT(level == PT_PAGE_TABLE_LEVEL);
			if (write) {
				if (!(*sptep & PT_WRITABLE_MASK)) {
					return NULL;
				}
				*sptep |= VMX_EPT_DIRTY_BIT;
			}
			return (u64 *)__va(*sptep & PT64_BASE_ADDR_MASK);
		}
		shadow_addr = *sptep & PT64_BASE_ADDR_MASK;
	}
	return NULL;
}

extern int tdp_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code,
			  bool prefault);

/* Translate gfn to kernel address through EPT */
void *rr_gfn_to_kaddr_ept(struct kvm_vcpu *vcpu, gfn_t gfn, int write)
{
	void *kaddr;
	int r;
	u32 error_code = 0;

	kaddr = __rr_gfn_to_kaddr_ept(vcpu, gfn, write);
	if (kaddr == NULL) {
		if (write)
			error_code = PFERR_WRITE_MASK;

		r = tdp_page_fault(vcpu, gfn_to_gpa(gfn), error_code, false);
		if (r < 0) {
			RR_DLOG(ERR, "error: vcpu=%d tdp_page_fault() returns "
				"%d for gfn 0x%llx", vcpu->vcpu_id, r, gfn);
			return NULL;
		}
		kaddr = __rr_gfn_to_kaddr_ept(vcpu, gfn, write);
		if (kaddr == NULL) {
			return NULL;
		}
	}
	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	return kaddr;
}
EXPORT_SYMBOL_GPL(rr_gfn_to_kaddr_ept);
