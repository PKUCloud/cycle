#ifndef __RECORD_REPLAY_H
#define __RECORD_REPLAY_H

#include <linux/kvm.h> /* ioctl definition */
#include <linux/kvm_types.h>
#include <linux/bitops.h>
#include <linux/mutex.h>

struct kvm;
struct kvm_vcpu;

#define RR_ASYNC_PREEMPTION_EPT	(KVM_RR_CTRL_MEM_EPT | KVM_RR_CTRL_MODE_ASYNC |\
				 KVM_RR_CTRL_KICK_PREEMPTION)

#define RR_DEFAULT_PREEMTION_TIMER_VAL	30000

#define RR_REQ_TLB_FLUSH		0
#define RR_REQ_REMOTE_TLB_FLUSH		1

#define RR_MAX_VCPUS			16

/* Whether this spte has been withdrawn read permission by CREW */
#define RR_PT_CREW_READ_TAG		(1ULL << 52)
/* Hints for the original permission info of this spte */
#define RR_PT_CREW_PERM_SHIFT		53
#define RR_PT_CREW_PERM_MASK		0x7ULL

struct rr_perm_req {
	struct list_head link;
	bool is_valid;
	gfn_t gfn;
	int write;
	int nr_ack_left;
	bool acks[RR_MAX_VCPUS];
	int vcpu_id;
};

/* Record and replay control info for a particular vcpu */
struct rr_vcpu_info {
	bool enabled;		/* State of record and replay */
	unsigned long requests;	/* Requests bitmap */
	bool is_master;
	struct rr_perm_req perm_req;
};

/* Record and replay control info for kvm */
struct rr_kvm_info {
	bool enabled;
	atomic_t nr_sync_vcpus;
	atomic_t nr_fin_vcpus;
	struct hlist_head *gfn_hash;	/* Hash table for gfn state */
	spinlock_t crew_lock;
	struct list_head req_list;
};

struct rr_gfn_state {
	struct hlist_node hlink;
	gfn_t gfn;
	/* The vcpu_id of this gfn's owner. -1 indicates that this gfn is
	 * shared.
	 */
	int owner_id;
};

void rr_vcpu_info_init(struct rr_vcpu_info *rr_info);
void rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info);
int rr_vcpu_enable(struct kvm_vcpu *vcpu);
void rr_vcpu_disable(struct kvm_vcpu *vcpu);
void rr_request_perm(struct kvm_vcpu *vcpu, gfn_t gfn, int write);
void rr_request_perm_post(struct kvm_vcpu *vcpu);
void rr_handle_perm_req(struct kvm_vcpu *vcpu);
void rr_clear_perm_req(struct kvm_vcpu *vcpu);
void rr_set_mmio_spte_mask(u64 mmio_mask);
int rr_page_fault_check(struct kvm_vcpu *vcpu, gfn_t gfn, int write);
void rr_fix_tagged_spte(u64 *sptep, const char *func_name);

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
