#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/vmx.h>
#include <linux/timer.h>

#include "mmu.h"

static struct timer_list rr_timer;

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

	vrr_info->enabled = true;

	RR_DLOG(INIT, "vcpu=%d rr_vcpu_info initialized", vcpu->vcpu_id);
}

static void rr_sample_ept(unsigned long data);

static void __rr_kvm_enable(struct kvm *kvm)
{
	struct rr_kvm_info *krr_info = &kvm->rr_info;

	setup_timer(&rr_timer, rr_sample_ept, (unsigned long)kvm);
	krr_info->last_jiffies = jiffies;
	krr_info->disabled_time = 0;
	krr_info->enabled_time = jiffies;
	krr_info->enabled = true;

	RR_DLOG(INIT, "rr_kvm_info initialized");
}

/* Initialization for RR_ASYNC_PREEMPTION_EPT */
static int __rr_crew_init(struct kvm_vcpu *vcpu)
{
	__rr_vcpu_enable(vcpu);

	if (vcpu->rr_info.is_master)
		vcpu->kvm->arch.mmu_valid_gen++;

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
	if (vcpu->rr_info.is_master) {
		vcpu->kvm->rr_info.last_jiffies = jiffies;
		mod_timer(&rr_timer,
			  jiffies + msecs_to_jiffies(RR_SAMPLE_INTERVAL));
	}
	return ret;
}
EXPORT_SYMBOL_GPL(rr_vcpu_enable);

static void __rr_print_sta(struct kvm *kvm)
{
	struct rr_kvm_info *krr_info = &kvm->rr_info;
	u64 temp;

	RR_LOG("=== Statistics for FT test ===\n");
	printk(KERN_INFO "=== Statistics for FT test ===\n");

	RR_LOG("HZ=%u\n", HZ);

	temp = krr_info->disabled_time - krr_info->enabled_time;
	RR_LOG("record_up_jiffies=%llu (%dms) (enabled=%llu disabled=%llu)\n",
	       temp, jiffies_to_msecs(temp),
	       krr_info->enabled_time, krr_info->disabled_time);
}

static int __rr_crew_disable(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	if (vrr_info->is_master) {
		krr_info->disabled_time = jiffies;
		krr_info->enabled = false;
		__rr_print_sta(vcpu->kvm);
	}

	vrr_info->enabled = false;

	RR_DLOG(INIT, "vcpu=%d disabled", vcpu->vcpu_id);
	return 0;
}

void rr_vcpu_disable(struct kvm_vcpu *vcpu)
{
	/* Delete the timer repeatedly is OK */
	del_timer(&rr_timer);
	__rr_vcpu_sync(vcpu, __rr_crew_disable, __rr_crew_disable, NULL);
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	printk(KERN_INFO "vcpu=%d disabled\n", vcpu->vcpu_id);
}
EXPORT_SYMBOL_GPL(rr_vcpu_disable);

/* Definitions from mmu.c */
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_NR_PT_ENTRY	512

#define SHADOW_PT_ADDR(address, index, level) \
	(address + (index << PT64_LEVEL_SHIFT(level)))

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
	if (is_large_pte(pte)) {
		RR_ERR("error: large pte=0x%llx level=%d", pte, level);
		return 1;
	}
	return 0;
}

void rr_set_mmio_spte_mask(u64 mmio_mask)
{
	RR_DLOG(INIT, "shadow_mmio_mask set to 0x%llx", mmio_mask);
	shadow_mmio_mask = mmio_mask;
}
EXPORT_SYMBOL_GPL(rr_set_mmio_spte_mask);

static void __rr_walk_ept(struct kvm_vcpu *vcpu, hpa_t shadow_addr, int level,
			  u64 *counter)
{
	u64 index;
	hpa_t new_addr;
	u64 *sptep;
	u64 spte;

	RR_ASSERT(level >= PT_PAGE_TABLE_LEVEL);

	for (index = 0; index < PT64_NR_PT_ENTRY; ++index) {
		sptep = ((u64 *)__va(shadow_addr)) + index;
		spte = *sptep;
		if (!is_shadow_present_pte(spte))
			continue;
		if (!(spte & VMX_EPT_ACCESS_BIT))
			continue;

		new_addr = spte & PT64_BASE_ADDR_MASK;
		if (is_last_spte(spte, level)) {
			if (spte & VMX_EPT_DIRTY_BIT) {
				(*counter)++;
				*sptep &= ~VMX_EPT_DIRTY_BIT;
			}
		} else {
			__rr_walk_ept(vcpu, new_addr, level - 1, counter);
		}
		*sptep &= ~VMX_EPT_ACCESS_BIT;
	}
}

/* Scan the EPT and get the num of dirty pages, as well as clean the dirty
 * bits.
 */
static int __rr_check_and_clean_ept(struct kvm *kvm, u64 *changed_pages)
{
	struct kvm_vcpu *vcpu = kvm->vcpus[0];
	int level;
	hpa_t shadow_addr;
	int ret = 0;

	spin_lock(&kvm->mmu_lock);
	if (unlikely(vcpu->vcpu_id != 0)) {
		RR_ERR("error: kvm parameter error");
		ret = -1;
		goto out;
	}
	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa)) {
		RR_ERR("error: invalid root_hpa=0x%llx",
		       vcpu->arch.mmu.root_hpa);
		ret = -1;
		goto out;
	}

	*changed_pages = 0;
	level = vcpu->arch.mmu.shadow_root_level;
	shadow_addr = vcpu->arch.mmu.root_hpa;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT((vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL) &&
		  vcpu->arch.mmu.direct_map);

	__rr_walk_ept(vcpu, shadow_addr, level, changed_pages);

out:
	spin_unlock(&kvm->mmu_lock);
	return ret;
}

/* Timer callback function */
static void rr_sample_ept(unsigned long data)
{
	struct kvm *kvm = (struct kvm *)data;
	u64 changed_pages = 0;
	int ret;

	ret = __rr_check_and_clean_ept(kvm, &changed_pages);
	if (likely(!ret)) {
		RR_LOG("jiffies %llu interval %llu pages %llu\n", jiffies,
		       jiffies - kvm->rr_info.last_jiffies, changed_pages);
		kvm->rr_info.last_jiffies = jiffies;
	}

	mod_timer(&rr_timer,
		  jiffies + msecs_to_jiffies(RR_SAMPLE_INTERVAL));
}

