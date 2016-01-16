#ifndef __RECORD_REPLAY_H
#define __RECORD_REPLAY_H

#include <linux/kvm.h> /* ioctl definition */
#include <linux/bitops.h>
#include <linux/mutex.h>

struct kvm;
struct kvm_vcpu;

/* Record and replay control info for a particular vcpu */
struct rr_vcpu_info {
	bool enabled;		/* State of record and replay */
	bool is_master;
};

/* Record and replay control info for kvm */
struct rr_kvm_info {
	bool enabled;
	atomic_t nr_sync_vcpus;
	atomic_t nr_fin_vcpus;
};

void rr_vcpu_info_init(struct rr_vcpu_info *rr_info);
void rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info);
int rr_vcpu_enable(struct kvm_vcpu *vcpu);
void rr_vcpu_disable(struct kvm_vcpu *vcpu);

#endif
