#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/vmx.h>

#include "mmu.h"

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

	vrr_info->nr_exits = 0;
	memset(vrr_info->exit_stat, 0, sizeof(vrr_info->exit_stat));
	vrr_info->exit_time = 0;
	vrr_info->cur_exit_time = 0;
	vrr_info->enabled = true;

	RR_DLOG(INIT, "vcpu=%d rr_vcpu_info initialized", vcpu->vcpu_id);
}

static void __rr_kvm_enable(struct kvm *kvm)
{
	struct rr_kvm_info *krr_info = &kvm->rr_info;

	krr_info->disabled_time = 0;
	rdtscll(krr_info->enabled_time);
	krr_info->enabled = true;

	RR_DLOG(INIT, "rr_kvm_info initialized");
}

/* Initialization for RR_ASYNC_PREEMPTION_EPT */
static int __rr_crew_init(struct kvm_vcpu *vcpu)
{
	/* MUST make rr_info.enabled true before separating page tables */
	__rr_vcpu_enable(vcpu);

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
	return ret;
}
EXPORT_SYMBOL_GPL(rr_vcpu_enable);

struct rr_exit_reason_str {
	u32 exit_reason;
	char *str;
};

static struct rr_exit_reason_str RR_VMX_EXIT_REASONS[] = {
	{ EXIT_REASON_EXCEPTION_NMI,         "EXCEPTION_NMI" },
	{ EXIT_REASON_EXTERNAL_INTERRUPT,    "EXTERNAL_INTERRUPT" },
	{ EXIT_REASON_TRIPLE_FAULT,          "TRIPLE_FAULT" },
	{ EXIT_REASON_PENDING_INTERRUPT,     "PENDING_INTERRUPT" },
	{ EXIT_REASON_NMI_WINDOW,            "NMI_WINDOW" },
	{ EXIT_REASON_TASK_SWITCH,           "TASK_SWITCH" },
	{ EXIT_REASON_CPUID,                 "CPUID" },
	{ EXIT_REASON_HLT,                   "HLT" },
	{ EXIT_REASON_INVLPG,                "INVLPG" },
	{ EXIT_REASON_RDPMC,                 "RDPMC" },
	{ EXIT_REASON_RDTSC,                 "RDTSC" },
	{ EXIT_REASON_VMCALL,                "VMCALL" },
	{ EXIT_REASON_VMCLEAR,               "VMCLEAR" },
	{ EXIT_REASON_VMLAUNCH,              "VMLAUNCH" },
	{ EXIT_REASON_VMPTRLD,               "VMPTRLD" },
	{ EXIT_REASON_VMPTRST,               "VMPTRST" },
	{ EXIT_REASON_VMREAD,                "VMREAD" },
	{ EXIT_REASON_VMRESUME,              "VMRESUME" },
	{ EXIT_REASON_VMWRITE,               "VMWRITE" },
	{ EXIT_REASON_VMOFF,                 "VMOFF" },
	{ EXIT_REASON_VMON,                  "VMON" },
	{ EXIT_REASON_CR_ACCESS,             "CR_ACCESS" },
	{ EXIT_REASON_DR_ACCESS,             "DR_ACCESS" },
	{ EXIT_REASON_IO_INSTRUCTION,        "IO_INSTRUCTION" },
	{ EXIT_REASON_MSR_READ,              "MSR_READ" },
	{ EXIT_REASON_MSR_WRITE,             "MSR_WRITE" },
	{ EXIT_REASON_MWAIT_INSTRUCTION,     "MWAIT_INSTRUCTION" },
	{ EXIT_REASON_MONITOR_INSTRUCTION,   "MONITOR_INSTRUCTION" },
	{ EXIT_REASON_PAUSE_INSTRUCTION,     "PAUSE_INSTRUCTION" },
	{ EXIT_REASON_MCE_DURING_VMENTRY,    "MCE_DURING_VMENTRY" },
	{ EXIT_REASON_TPR_BELOW_THRESHOLD,   "TPR_BELOW_THRESHOLD" },
	{ EXIT_REASON_APIC_ACCESS,           "APIC_ACCESS" },
	{ EXIT_REASON_EPT_VIOLATION,         "EPT_VIOLATION" },
	{ EXIT_REASON_EPT_MISCONFIG,         "EPT_MISCONFIG" },
	{ EXIT_REASON_WBINVD,                "WBINVD" },
	{ EXIT_REASON_APIC_WRITE,            "APIC_WRITE" },
	{ EXIT_REASON_EOI_INDUCED,           "EOI_INDUCED" },
	{ EXIT_REASON_INVALID_STATE,         "INVALID_STATE" },
	{ EXIT_REASON_INVD,                  "INVD" },
	{ EXIT_REASON_INVPCID,               "INVPCID" },
	{ EXIT_REASON_PREEMPTION_TIMER,      "PREEMPTION_TIMER" },
};

static inline char *__rr_exit_reason_to_str(u32 exit_reason)
{
	int i;

	for (i = 0; i < RR_NR_EXIT_REASON_MAX; ++i) {
		if (RR_VMX_EXIT_REASONS[i].exit_reason == exit_reason)
			return RR_VMX_EXIT_REASONS[i].str;
	}
	return "[unknown reason]";
}

static void __rr_print_sta(struct kvm *kvm)
{
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	int i;
	struct kvm_vcpu *vcpu_it;
	u64 nr_exits = 0;
	u64 exit_time = 0;
	u64 temp;
	struct rr_kvm_info *krr_info = &kvm->rr_info;
	u32 exit_reason;
	u64 cal_exit_reason = 0;
	u64 cal_exit_time = 0;
	u64 temp_exit_time, temp_exit_counter;
	struct rr_exit_stat *exit_stat;

	RR_LOG("=== Statistics for Baseline ===\n");
	printk(KERN_INFO "=== Statistics for Baseline ===\n");
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_it = kvm->vcpus[i];
		temp = vcpu_it->rr_info.nr_exits;
		nr_exits += temp;
		RR_LOG("vcpu=%d nr_exits=%lld\n", vcpu_it->vcpu_id,
		       temp);
		printk(KERN_INFO "vcpu=%d nr_exits=%lld\n", vcpu_it->vcpu_id,
		       temp);
	}
	RR_LOG("total nr_exits=%lld\n", nr_exits);
	printk(KERN_INFO "total nr_exits=%lld\n", nr_exits);

	RR_LOG(">>> Stat for exit reasons:\n");
	for (exit_reason = 0; exit_reason < RR_NR_EXIT_REASON_MAX;
	     ++exit_reason) {
		temp_exit_counter = 0;
		temp_exit_time = 0;
		for (i = 0; i < online_vcpus; ++i) {
			exit_stat = &(kvm->vcpus[i]->rr_info.exit_stat[exit_reason]);
			temp_exit_counter += exit_stat->counter;
			temp_exit_time += exit_stat->time;
		}
		if (temp_exit_counter == 0) {
			if (temp_exit_time != 0) {
				RR_ERR("error: exit_reason=%d counter=%llu "
				       "time=%llu", exit_reason,
				       temp_exit_counter, temp_exit_time);
			}
			continue;
		}

		if (exit_reason < RR_EXIT_REASON_MAX) {
			cal_exit_reason += temp_exit_counter;
			cal_exit_time += temp_exit_time;
		}

		RR_LOG("%s(#%u)=%llu time=%llu\n",
		       __rr_exit_reason_to_str(exit_reason),
		       exit_reason, temp_exit_counter, temp_exit_time);
	}
	if (cal_exit_reason != nr_exits) {
		RR_ERR("error: calculated_nr_exits=%llu != nr_exits=%llu",
		       cal_exit_reason, nr_exits);
	}

	RR_LOG(">>> Stat for time:\n");
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_it = kvm->vcpus[i];
		temp = vcpu_it->rr_info.exit_time;
		exit_time += temp;
		RR_LOG("vcpu=%d exit_time=%llu\n", vcpu_it->vcpu_id, temp);
	}
	RR_LOG("total exit_time=%llu\n", exit_time);

	if (exit_time != cal_exit_time) {
		RR_ERR("error: calculated_exit_time=%llu != "
		       "exit_time=%llu", cal_exit_time, exit_time);
	}

	if (krr_info->enabled_time >= krr_info->disabled_time) {
		temp = (~0ULL) - krr_info->enabled_time +
		       krr_info->disabled_time;
		RR_ERR("warning: time wrapped");
	} else
		temp = krr_info->disabled_time - krr_info->enabled_time;

	RR_LOG("record_up_time=%llu (enabled=%llu disabled=%llu)\n",
	       temp, krr_info->enabled_time, krr_info->disabled_time);
}

static int __rr_crew_disable(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	if (vrr_info->is_master) {
		rdtscll(krr_info->disabled_time);
		krr_info->enabled = false;
		__rr_print_sta(vcpu->kvm);
	}

	vrr_info->enabled = false;

	RR_DLOG(INIT, "vcpu=%d disabled", vcpu->vcpu_id);
	return 0;
}

void rr_vcpu_disable(struct kvm_vcpu *vcpu)
{
	__rr_vcpu_sync(vcpu, __rr_crew_disable, __rr_crew_disable, NULL);
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	printk(KERN_INFO "vcpu=%d disabled\n", vcpu->vcpu_id);
}
EXPORT_SYMBOL_GPL(rr_vcpu_disable);

