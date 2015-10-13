#ifndef ASM_X86_CHECKPOINT_ROLLBACK_H
#define ASM_X86_CHECKPOINT_ROLLBACK_H

struct kvm;
struct kvm_vcpu;

struct rr_MSRdata{
	struct kvm_msrs info;
	struct kvm_msr_entry entries[100];
};

struct rr_lapic {
	/* The highest vector set in ISR; if -1 - invalid, must scan ISR. */
	int highest_isr_cache;
	/*
	 * APIC register page.  The layout matches the register layout seen by
	 * the guest 1:1, because it is accessed by the vmx microcode.
	 * Note: Only one register, the TPR, is used by the microcode.
	 */
	char regs[KVM_APIC_REG_SIZE];
};

struct rr_CPUX86State {
	/* Standard registers */
	struct kvm_regs kvm_regs;

	/* FPU state */
	struct kvm_fpu fpu;
	struct kvm_xsave xsave;
	struct kvm_xcrs xcrs;
	struct kvm_mp_state mp_state;

	struct rr_lapic lapic;
	/* Debug registers */
	struct kvm_debugregs dbgregs;
	/* Segments */
	struct kvm_sregs sregs;

	struct kvm_vcpu_events vcpu_events;
	/* MSRs */
	struct rr_MSRdata msr_data;
};

int rr_do_vcpu_checkpoint(struct kvm_vcpu *vcpu);
int rr_do_vcpu_rollback(struct kvm_vcpu *vcpu);
#endif

