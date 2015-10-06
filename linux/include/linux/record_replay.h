#ifndef __RECORD_REPLAY_H
#define __RECORD_REPLAY_H

#include <linux/kvm.h> /* ioctl definition */

struct kvm;
struct kvm_vcpu;

#define RR_ASYNC_PREEMPTION_EPT	(KVM_RR_CTRL_MEM_EPT | KVM_RR_CTRL_MODE_ASYNC |\
				 KVM_RR_CTRL_KICK_PREEMPTION)

/* Record and replay control info for a particular vcpu */
struct rr_vcpu_info {
	bool enabled;	/* State of record and replay */
};

/* Record and replay control info for kvm */
struct rr_kvm_info {
	atomic_t nr_sync_vcpus;
	atomic_t nr_fin_vcpus;
};

int rr_vcpu_info_init(struct rr_vcpu_info *rr_info);
int rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info);
int rr_vcpu_enable(struct kvm_vcpu *vcpu);

void rr_test(void);

#endif
