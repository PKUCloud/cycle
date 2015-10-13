#ifndef __RECORD_REPLAY_H
#define __RECORD_REPLAY_H

#include <linux/kvm.h> /* ioctl definition */
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kvm_types.h>
#include <asm/checkpoint_rollback.h>

struct kvm;
struct kvm_vcpu;

#define RR_ASYNC_PREEMPTION_EPT	(KVM_RR_CTRL_MEM_EPT | KVM_RR_CTRL_MODE_ASYNC |\
				 KVM_RR_CTRL_KICK_PREEMPTION)

#define RR_DEFAULT_PREEMTION_TIMER_VAL	30000

#define RR_CHUNK_COMMIT			0
#define RR_CHUNK_ROLLBACK		1
#define RR_CHUNK_SKIP			2

#define RR_REQ_CHECKPOINT		0
#define RR_REQ_COMMIT_MEMORY		1
#define RR_REQ_POST_CHECK		2

struct rr_event {
	struct list_head link;
	int delivery_mode;
	int vector;
	int level;
	int trig_mode;
	unsigned long *dest_map;
};

/* Structure for keeping info about memory cow mapping */
struct rr_cow_page {
	struct list_head link;
	gfn_t gfn;
	pfn_t orig_pfn;
	pfn_t priv_pfn;
	/* Pointer to the spte which references this pfn */
	u64 *sptep;
};

/* Record and replay control info for a particular vcpu */
struct rr_vcpu_info {
	bool enabled;		/* State of record and replay */
	u32 timer_value;	/* Preemption timer value of this vcpu */
	unsigned long requests;	/* Requests bitmap */
	struct mutex event_list_lock;
	struct list_head event_list;
	struct rr_CPUX86State vcpu_checkpoint;
	struct list_head cow_pages;
	int nr_cow_pages;
};

/* Record and replay control info for kvm */
struct rr_kvm_info {
	atomic_t nr_sync_vcpus;
	atomic_t nr_fin_vcpus;
};

struct rr_ops {
	void (*ape_vmx_setup)(u32 timer_value);
};

int rr_init(struct rr_ops *rr_ops);
int rr_vcpu_info_init(struct rr_vcpu_info *rr_info);
int rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info);
int rr_vcpu_enable(struct kvm_vcpu *vcpu);
void rr_vcpu_checkpoint(struct kvm_vcpu *vcpu);
void rr_vcpu_rollback(struct kvm_vcpu *vcpu);
void rr_vcpu_commit_memory_again(struct kvm_vcpu *vcpu);
void rr_vcpu_post_check(struct kvm_vcpu *vcpu);
int rr_vcpu_check_chunk(struct kvm_vcpu *vcpu);
void rr_vcpu_add_irq(struct kvm_vcpu *vcpu, int delivery_mode, int vector,
		     int level, int trig_mode, unsigned long *dest_map);
void rr_vcpu_reinject_irq(struct kvm_vcpu *vcpu);
void rr_vcpu_memory_cow(struct kvm_vcpu *vcpu, u64 *sptep, gfn_t gfn,
			pfn_t pfn);
void *rr_gfn_to_kaddr_ept(struct kvm_vcpu *vcpu, gfn_t gfn, int write);

static inline void rr_make_request(int req, struct rr_vcpu_info *rr_info)
{
	set_bit(req, &rr_info->requests);
}

static inline bool rr_check_request(int req, struct rr_vcpu_info *rr_info)
{
	return test_bit(req, &rr_info->requests);
}

static inline void rr_clear_request(int req, struct rr_vcpu_info *rr_info)
{
	clear_bit(req, &rr_info->requests);
}

static inline void rr_clear_all_request(struct rr_vcpu_info *rr_info)
{
	rr_info->requests = 0;
}
#endif
