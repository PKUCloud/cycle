#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>

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
	RR_DLOG(INIT, "vcpu=%d start", vcpu->vcpu_id);
	vcpu->rr_info.enabled = true;
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return 0;
}

int rr_vcpu_info_init(struct rr_vcpu_info *rr_info)
{
	rr_info->enabled = false;
	return 0;
}

int rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info)
{
	atomic_set(&rr_kvm_info->nr_sync_vcpus, 0);
	atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	return 0;
}

int rr_vcpu_enable(struct kvm_vcpu *vcpu)
{
	int ret;

	RR_DLOG(INIT, "vcpu=%d start", vcpu->vcpu_id);
	ret = __rr_vcpu_sync(vcpu, __rr_ape_init, __rr_ape_init);
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return ret;
}

void rr_test(void)
{
	RR_DLOG(ERR, "Hello, RR_ASYNC_PREEMPTION_EPT is %d",
		RR_ASYNC_PREEMPTION_EPT);
}
