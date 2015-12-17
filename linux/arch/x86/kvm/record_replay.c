#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>

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
	return 0;
}

void rr_vcpu_disable(struct kvm_vcpu *vcpu)
{
	__rr_vcpu_sync(vcpu, __rr_crew_disable, __rr_crew_disable,
		       __rr_crew_post_disable);

	kvm_mmu_unload(vcpu);
	kvm_mmu_reload(vcpu);
	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	printk(KERN_INFO "vcpu=%d disabled\n", vcpu->vcpu_id);
}
EXPORT_SYMBOL_GPL(rr_vcpu_disable);

