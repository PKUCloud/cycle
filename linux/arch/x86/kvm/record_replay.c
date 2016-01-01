#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/vmx.h>

#include "mmu.h"
#include "rr_hash.h"

/* Synchronize all vcpus before enabling record and replay.
 * Master will do master_pre_func before slaves and then master_post_func
 * after slaves. After calling this function, @nr_sync_vcpus and
 * @nr_fin_vcpus will be set to 0.
 */
static int __rr_vcpu_sync(struct kvm_vcpu *vcpu,
			  int (*master_pre_func)(struct kvm_vcpu *vcpu),
			  int (*slave_func)(struct kvm_vcpu *vcpu),
			  int (*master_post_func)(struct kvm_vcpu *vcpu))
{
	int ret = 0;
	struct kvm *kvm = vcpu->kvm;
	struct rr_kvm_info *rr_kvm_info = &kvm->rr_info;
	int i;
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	bool is_master = false;

	if (atomic_inc_return(&rr_kvm_info->nr_sync_vcpus) == 1) {
		is_master = true;
		vcpu->rr_info.is_master = true;
	} else {
		vcpu->rr_info.is_master = false;
	}

	if (is_master) {
		RR_DLOG(INIT, "vcpu=%d is the master", vcpu->vcpu_id);
		for (i = 0; i < online_vcpus; ++i) {
			if (kvm->vcpus[i] == vcpu)
				continue;
			RR_DLOG(INIT, "vcpu=%d kick vcpu=%d", vcpu->vcpu_id,
				kvm->vcpus[i]->vcpu_id);
			kvm_make_request(KVM_REQ_EVENT, kvm->vcpus[i]);
			kvm_vcpu_kick(kvm->vcpus[i]);
		}
		RR_DLOG(INIT, "vcpu=%d wait for other vcpus to sync",
			vcpu->vcpu_id);
		/* After all vcpus have come in, master will go first while
		 * slaves will wait until master finishes.
		 */
		while (atomic_read(&rr_kvm_info->nr_sync_vcpus) < online_vcpus) {
			msleep(1);
		}
		/* Do master things here */
		if (master_pre_func)
			ret = master_pre_func(vcpu);
		/* Let slaves begin */
		atomic_set(&rr_kvm_info->nr_sync_vcpus, 0);
	} else {
		RR_DLOG(INIT, "vcpu=%d is the slave", vcpu->vcpu_id);
		while (atomic_read(&rr_kvm_info->nr_sync_vcpus) != 0) {
			msleep(1);
		}
		/* Do slave things here */
		if (slave_func)
			ret = slave_func(vcpu);
	}
	atomic_inc(&rr_kvm_info->nr_fin_vcpus);
	if (is_master) {
		while (atomic_read(&rr_kvm_info->nr_fin_vcpus) < online_vcpus) {
			msleep(1);
		}
		if (master_post_func)
			ret = master_post_func(vcpu);
		atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	} else {
		while (atomic_read(&rr_kvm_info->nr_fin_vcpus) != 0) {
			msleep(1);
		}
	}
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return ret;
}

static void __rr_vcpu_enable(struct kvm_vcpu *vcpu)
{
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	vrr_info->requests = 0;
	vrr_info->perm_req.vcpu_id = vcpu->vcpu_id;
	init_waitqueue_head(&(vrr_info->perm_req.queue));
	vrr_info->enabled = true;

	RR_DLOG(INIT, "vcpu=%d rr_vcpu_info initialized", vcpu->vcpu_id);
}

static void __rr_kvm_enable(struct kvm *kvm)
{
	struct rr_kvm_info *krr_info = &kvm->rr_info;

	rr_init_hash(&krr_info->gfn_hash);
	krr_info->enabled = true;

	RR_DLOG(INIT, "rr_kvm_info initialized");
}

/* Initialization for RR_ASYNC_PREEMPTION_EPT */
static int __rr_crew_init(struct kvm_vcpu *vcpu)
{
	/* MUST make rr_info.enabled true before separating page tables */
	__rr_vcpu_enable(vcpu);

	/* Obsolete existing paging structures to separate page tables of
	 * different vcpus.
	 */
	if (vcpu->rr_info.is_master) {
		vcpu->kvm->arch.mmu_valid_gen++;
	}
	kvm_mmu_unload(vcpu);
	kvm_mmu_reload(vcpu);

	RR_DLOG(INIT, "vcpu=%d enabled, root_hpa=0x%llx",
		vcpu->vcpu_id, vcpu->arch.mmu.root_hpa);
	return 0;
}

static int __rr_crew_post_init(struct kvm_vcpu *vcpu)
{
	RR_ASSERT(vcpu->rr_info.is_master);
	__rr_kvm_enable(vcpu->kvm);
	return 0;
}

void rr_vcpu_info_init(struct rr_vcpu_info *rr_info)
{
	memset(rr_info, 0, sizeof(*rr_info));
	rr_info->enabled = false;
	rr_info->requests = 0;
	rr_info->is_master = false;

	RR_DLOG(INIT, "rr_vcpu_info initialized partially");
}
EXPORT_SYMBOL_GPL(rr_vcpu_info_init);

void rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info)
{
	memset(rr_kvm_info, 0, sizeof(*rr_kvm_info));
	rr_kvm_info->enabled = false;
	atomic_set(&rr_kvm_info->nr_sync_vcpus, 0);
	atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	spin_lock_init(&rr_kvm_info->crew_lock);
	INIT_LIST_HEAD(&rr_kvm_info->req_list);
	atomic_set(&rr_kvm_info->in_dma, 0);

	RR_DLOG(INIT, "rr_kvm_info initialized partially");
}
EXPORT_SYMBOL_GPL(rr_kvm_info_init);

int rr_vcpu_enable(struct kvm_vcpu *vcpu)
{
	int ret;

	RR_DLOG(INIT, "vcpu=%d start", vcpu->vcpu_id);
	ret = __rr_vcpu_sync(vcpu, __rr_crew_init, __rr_crew_init,
			     __rr_crew_post_init);
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	printk(KERN_INFO "vcpu=%d enabled\n", vcpu->vcpu_id);
	return ret;
}
EXPORT_SYMBOL_GPL(rr_vcpu_enable);

static int __rr_crew_disable(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	if (vrr_info->is_master) {
		krr_info->enabled = false;
	}

	vrr_info->enabled = false;
	rr_clear_all_request(vrr_info);

	RR_DLOG(INIT, "vcpu=%d disabled", vcpu->vcpu_id);
	return 0;
}

static int __rr_crew_post_disable(struct kvm_vcpu *vcpu)
{
	int i;
	struct hlist_head *phead;
	struct hlist_node *tmp;
	struct rr_gfn_state *gfnsta;
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct rr_perm_req *req, *tmp_req;

	vcpu->kvm->arch.mmu_valid_gen++;

	/* Clear hash */
	for (i = 0; i < RR_HASH_SIZE; ++i) {
		phead = &krr_info->gfn_hash[i];
		hlist_for_each_entry_safe(gfnsta, tmp, phead, hlink) {
			hlist_del(&gfnsta->hlink);
			kfree(gfnsta);
		}
	}
	rr_clear_hash(&krr_info->gfn_hash);

	/* Clear perm_req list */
	list_for_each_entry_safe(req, tmp_req, &vcpu->kvm->rr_info.req_list,
				 link) {
		list_del(&req->link);
	}
	return 0;
}

void rr_vcpu_disable(struct kvm_vcpu *vcpu)
{
	vcpu->rr_info.perm_req.is_valid = false;
	wake_up_interruptible(&vcpu->rr_info.perm_req.queue);
	__rr_vcpu_sync(vcpu, __rr_crew_disable, __rr_crew_disable,
		       __rr_crew_post_disable);

	kvm_mmu_unload(vcpu);
	kvm_mmu_reload(vcpu);
	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	printk(KERN_INFO "vcpu=%d disabled\n", vcpu->vcpu_id);
}
EXPORT_SYMBOL_GPL(rr_vcpu_disable);

/* Macros from mmu.c */
#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#define RR_PT_ALL	 (PT_PRESENT_MASK | PT_WRITABLE_MASK | PT_USER_MASK)

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))
#define PT_FIRST_AVAIL_BITS_SHIFT 10
#define SPTE_MMU_WRITEABLE	(1ULL << (PT_FIRST_AVAIL_BITS_SHIFT + 1))

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_NR_PT_ENTRY	512

#define SHADOW_PT_ADDR(address, index, level) \
	(address + (index << PT64_LEVEL_SHIFT(level)))

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))

#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

static u64 __read_mostly shadow_mmio_mask;

static inline bool is_mmio_spte(u64 spte)
{
	return (spte & shadow_mmio_mask) == shadow_mmio_mask;
}

static inline int is_shadow_present_pte(u64 pte)
{
	return pte & PT_PRESENT_MASK && !is_mmio_spte(pte);
}

static int inline is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static int inline is_last_spte(u64 pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return 1;
	if (is_large_pte(pte))
		return 1;
	return 0;
}

void rr_set_mmio_spte_mask(u64 mmio_mask)
{
	RR_DLOG(INIT, "shadow_mmio_mask set to 0x%llx", mmio_mask);
	shadow_mmio_mask = mmio_mask;
}
EXPORT_SYMBOL_GPL(rr_set_mmio_spte_mask);

static inline void rr_pt_set_read_tag(u64 *sptep)
{
	u64 spte = *sptep;

	RR_ASSERT(!(spte & RR_PT_CREW_READ_TAG));
	spte |= RR_PT_CREW_READ_TAG;
	spte |= ((spte & RR_PT_CREW_PERM_MASK) << RR_PT_CREW_PERM_SHIFT);
	*sptep = spte;
}

static inline void rr_pt_clear_read_tag(u64 *sptep)
{
	u64 spte = *sptep;

	spte &= ~RR_PT_CREW_READ_TAG;
	spte &= ~(RR_PT_CREW_PERM_MASK << RR_PT_CREW_PERM_SHIFT);
	*sptep = spte;
}

static inline void rr_pt_restore_perm(u64 *sptep)
{
	u64 spte = *sptep;

	spte &= ~RR_PT_CREW_PERM_MASK;
	spte |= ((spte >> RR_PT_CREW_PERM_SHIFT) & RR_PT_CREW_PERM_MASK);
	*sptep = spte;
}

static inline bool rr_pt_check_read_tag(u64 spte)
{
	return (spte & RR_PT_CREW_READ_TAG) != 0;
}

/* Fix a tagged spte. All permission of this spte was removed. But in some
 * cases, we need to fix it.
 */
void rr_fix_tagged_spte(u64 *sptep)
{
	RR_ASSERT(sptep);
	if (rr_pt_check_read_tag(*sptep)) {
		rr_pt_restore_perm(sptep);
		rr_pt_clear_read_tag(sptep);
	}
}
EXPORT_SYMBOL_GPL(rr_fix_tagged_spte);

static inline bool rr_ept_set_perm_by_gfn(struct kvm_vcpu *vcpu, gfn_t gfn,
					  int write)
{
	int level = vcpu->arch.mmu.shadow_root_level;
	hpa_t addr = (u64)gfn << PAGE_SHIFT;
	hpa_t shadow_addr = vcpu->arch.mmu.root_hpa;
	unsigned index;
	u64 *sptep;
	u64 old_spte;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT(shadow_addr != INVALID_PAGE);

	for (; level >= PT_PAGE_TABLE_LEVEL; --level) {
		index = SHADOW_PT_INDEX(addr, level);
		sptep = ((u64 *)__va(shadow_addr)) + index;
		old_spte = *sptep;
		if (unlikely(!is_shadow_present_pte(old_spte))) {
			return false;
		}
		if (is_last_spte(old_spte, level)) {
			if (write) {
				rr_pt_set_read_tag(sptep);
				*sptep &= ~RR_PT_ALL;
			} else {
				rr_fix_tagged_spte(sptep);
				*sptep &= ~PT_WRITABLE_MASK;
			}
			RR_DLOG(MMU, "set v=%d gfn=0x%llx spte=0x%llx -> "
				"0x%llx", vcpu->vcpu_id, gfn, old_spte, *sptep);
			return true;
		}
		shadow_addr = *sptep & PT64_BASE_ADDR_MASK;
	}
	return false;
}

/* Should be called within krr_info.crew_lock.
 * Change ept of all vcpus and add a req node to the krr_info.req_list.
 */
void rr_request_perm(struct kvm_vcpu *vcpu, gfn_t gfn, int write)
{
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct kvm *kvm = vcpu->kvm;
	struct rr_kvm_info *krr_info = &kvm->rr_info;
	struct rr_perm_req *req = &vrr_info->perm_req;
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	int i;
	struct kvm_vcpu *vcpu_iter;
	bool need_tlb_flush = false;

	RR_DLOG(MMU, "vcpu=%d gfn=0x%llx write=%d", vcpu->vcpu_id,
		gfn, write);
	req->gfn = gfn;
	req->write = write;
	req->nr_ack_left = online_vcpus - 1;
	req->sptep = NULL;
	memset(req->acks, 0, sizeof(req->acks));

	rr_make_request(RR_REQ_TLB_FLUSH, vrr_info);

	/* If it is already valid, it means that this vcpu page fault again
	 * before accessing the last one.
	 */
	if (!req->is_valid) {
		req->is_valid = true;
		req->nr_not_accessed = 0;
		list_add_tail(&req->link, &krr_info->req_list);
	}

	/* Set other vcpus' ept */
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_iter = kvm->vcpus[i];
		if (vcpu_iter == vcpu)
			continue;
		if (rr_ept_set_perm_by_gfn(vcpu_iter, gfn, write))
			need_tlb_flush = true;
	}

	if (need_tlb_flush)
		rr_make_request(RR_REQ_REMOTE_TLB_FLUSH, vrr_info);
}
EXPORT_SYMBOL_GPL(rr_request_perm);

/* After page_fault handler, we need to sync with other vcpus */
void rr_request_perm_post(struct kvm_vcpu *vcpu)
{
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct rr_perm_req *my_req = &vrr_info->perm_req;

	if (rr_check_request(RR_REQ_REMOTE_TLB_FLUSH, vrr_info)) {
		rr_clear_request(RR_REQ_REMOTE_TLB_FLUSH, vrr_info);

		if (my_req->is_valid && (my_req->nr_ack_left > 0)) {
			kvm_flush_remote_tlbs(vcpu->kvm);
		}
	}
}
EXPORT_SYMBOL_GPL(rr_request_perm_post);

static inline void rr_handle_perm_req_one(struct kvm_vcpu *vcpu,
					  struct rr_perm_req *req)
{
	RR_DLOG(MMU, "vcpu=%d ack req=%d gfn=0x%llx", vcpu->vcpu_id,
		req->vcpu_id, req->gfn);
	req->acks[vcpu->vcpu_id] = true;
	req->nr_ack_left--;
	rr_make_request(RR_REQ_TLB_FLUSH, &vcpu->rr_info);
}

/* Check if there is any other vcpus' req we need to ack */
void rr_handle_perm_req(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct rr_perm_req *req;
	struct list_head *head = &krr_info->req_list;

	spin_lock(&krr_info->crew_lock);
	list_for_each_entry(req, head, link) {
		if (req->vcpu_id == vcpu->vcpu_id)
			continue;

		if (req->nr_ack_left > 0 && !req->acks[vcpu->vcpu_id]) {
			rr_handle_perm_req_one(vcpu, req);
		}
	}
	spin_unlock(&krr_info->crew_lock);
}
EXPORT_SYMBOL_GPL(rr_handle_perm_req);

void rr_clear_perm_req(struct kvm_vcpu *vcpu)
{
	struct rr_perm_req *my_req = &vcpu->rr_info.perm_req;

	RR_ASSERT(my_req->is_valid);
	spin_lock(&vcpu->kvm->rr_info.crew_lock);
	list_del(&my_req->link);
	my_req->is_valid = false;
	spin_unlock(&vcpu->kvm->rr_info.crew_lock);
	wake_up_interruptible(&my_req->queue);
}
EXPORT_SYMBOL_GPL(rr_clear_perm_req);


/* If one req is not accessed, we should not kick it out even if both gfns are
 * not conflicted.
 */
static inline bool rr_perm_req_conflict(struct rr_perm_req *req, gfn_t gfn)
{
	u64 *sptep = req->sptep;

	/* if sptep is NULL, it means that vcpu is in __direct_map and has not
	 * set the sptep yet.
	 */
	if (!sptep)
		return req->gfn == gfn;
	else
		return !(*sptep & VMX_EPT_ACCESS_BIT);
}

/* Should be called within krr_info.crew_lock.
 * Check if there is any req in the krr_info.req_list conflict with @gfn.
 * Return 0 indicates there is conflict and should not continue page fault
 * handling.
 */
struct rr_perm_req *rr_page_fault_check(struct kvm_vcpu *vcpu, gfn_t gfn,
					int write)
{
	struct rr_perm_req *req;
	struct list_head *head = &vcpu->kvm->rr_info.req_list;

	list_for_each_entry(req, head, link) {
		if (req->vcpu_id == vcpu->vcpu_id)
			continue;

		/* When disabled, the req in the list may be invalid */
		if (unlikely(!req->is_valid)) {
			RR_ASSERT(!rr_ctrl.enabled);
			continue;
		}

		if (rr_perm_req_conflict(req, gfn)) {
			RR_DLOG(MMU, "vcpu=%d gfn=0x%llx write=%d fail",
				vcpu->vcpu_id, gfn, write);
			return req;
		}
	}

	RR_DLOG(MMU, "vcpu=%d gfn=0x%llx write=%d pass",
		vcpu->vcpu_id, gfn, write);
	return NULL;
}
EXPORT_SYMBOL_GPL(rr_page_fault_check);

