#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/slab.h>
#include <asm/checkpoint_rollback.h>
#include <asm/processor.h>
#include <asm/kvm_para.h>
#include <asm/msr-index.h>
#include <asm/logger.h>

#include "irq.h"
#include "mmu.h"

static inline int kvm_has_feature(unsigned int feature)
{
	if (cpuid_eax(KVM_CPUID_FEATURES) & (1UL << feature))
		return 1;
	else
		return 0;
}

static int kvm_getset_regs(struct kvm_vcpu *vcpu, struct rr_CPUX86State *env,
			   int set)
{
	struct kvm_regs *kvm_regs = &env->kvm_regs;

	if (!set) {
		memset(kvm_regs, 0, sizeof(struct kvm_regs));
	}
	return kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_REGS : KVM_GET_REGS, kvm_regs);
}

static int kvm_getset_fpu(struct kvm_vcpu *vcpu, struct rr_CPUX86State *env,
			  int set)
{
	struct kvm_fpu *fpu = &env->fpu;

	if (!set){
		memset(fpu, 0, sizeof(struct kvm_fpu));
	}
	return kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_FPU : KVM_GET_FPU, fpu);
}

static int kvm_getset_xsave(struct kvm_vcpu *vcpu, struct rr_CPUX86State *env,
			    int set)
{
	struct kvm_xsave *xsave = &env->xsave;
	int ret = -ENOMEM;

	if (!cpu_has_xsave) {
		return kvm_getset_fpu(vcpu, env, set);
	}
	if (!set) {
		memset(xsave, 0, sizeof(struct kvm_xsave));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_XSAVE : KVM_GET_XSAVE, xsave);
	return ret;
}

static int kvm_getset_xcrs(struct kvm_vcpu *vcpu, struct rr_CPUX86State *env,
			   int set)
{
	struct kvm_xcrs *xcrs = &env->xcrs;
	int ret;

	if (!cpu_has_xsave) {
		return 0;
	}
	if (!set) {
		memset(xcrs, 0, sizeof(struct kvm_xcrs));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_XCRS : KVM_GET_XCRS, xcrs);
	return ret;
}

static int kvm_getset_mp_state(struct kvm_vcpu *vcpu,
			       struct rr_CPUX86State *env, int set)
{
	struct kvm_mp_state *mp_state = &env->mp_state;
	int ret = -ENOMEM;

	if (!set) {
		memset(mp_state, 0, sizeof(struct kvm_mp_state));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_MP_STATE : KVM_GET_MP_STATE,
				mp_state);
	return ret;
}

static int kvm_getset_apic(struct kvm_vcpu *vcpu,struct rr_CPUX86State *env,
			   int set)
{
	struct rr_lapic *lapic = &env->lapic;
	int ret;

	if (!set) {
		memset(lapic, 0, sizeof(struct rr_lapic));
	}
	if (irqchip_in_kernel(vcpu->kvm)) {
		ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_LAPIC : KVM_GET_LAPIC, lapic);
		return ret;
	}
	return 0;
}

static int kvm_getset_debugregs(struct kvm_vcpu *vcpu,
				struct rr_CPUX86State *env, int set)
{
	struct kvm_debugregs *dbgregs = &env->dbgregs;
	int ret = -ENOMEM;

	if (!set) {
		memset(dbgregs, 0, sizeof(struct kvm_debugregs));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_DEBUGREGS : KVM_GET_DEBUGREGS,
				dbgregs);
	return ret;
}

static int kvm_getset_vcpu_events(struct kvm_vcpu *vcpu,
				  struct rr_CPUX86State *env, int set)
{
	struct kvm_vcpu_events *events = &env->vcpu_events;
	int ret = -ENOMEM;

	if (!set) {
		memset(events, 0, sizeof(struct kvm_vcpu_events));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_VCPU_EVENTS : KVM_GET_VCPU_EVENTS,
				events);
	return ret;
}

static int kvm_getset_sregs(struct kvm_vcpu *vcpu, struct rr_CPUX86State *env,
			    int set)
{
	struct kvm_sregs *sregs = &env->sregs;
	int ret = -ENOMEM;

	if (!set) {
		memset(sregs, 0, sizeof(struct kvm_sregs));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_SREGS : KVM_GET_SREGS, sregs);
	return ret;
}

static int kvm_getset_msrs(struct kvm_vcpu *vcpu, struct rr_CPUX86State *env,
			   int set)
{
	struct rr_MSRdata *msr_data = &env->msr_data;
	struct kvm_msr_entry *msrs = msr_data->entries;
	int ret = -ENOMEM, n = 0, i = 0;
	uint64_t mcg_cap  = 0;

	if (!set) {
		memset(msr_data, 0, sizeof(struct rr_MSRdata));
		n = 0;

		msrs[n++].index = MSR_IA32_SYSENTER_CS;
		msrs[n++].index = MSR_IA32_SYSENTER_ESP;
		msrs[n++].index = MSR_IA32_SYSENTER_EIP;
		msrs[n++].index = MSR_IA32_CR_PAT;

		/* Need to check if our vcpu really has these msrs !
		 * If you really want to check this,
		 * use ioctl "KVM_GET_MSR_INDEX_LIST".
		 */
		msrs[n++].index = MSR_STAR;

		/* we don't have this */
		/* msrs[n++].index = MSR_VM_HSAVE_PA; */

		/* Emulated msrs */
		msrs[n++].index = MSR_IA32_TSCDEADLINE;
		msrs[n++].index = MSR_IA32_MISC_ENABLE;

		msrs[n++].index = MSR_IA32_TSC;

#ifdef CONFIG_X86_64
		msrs[n++].index = MSR_CSTAR;
		msrs[n++].index = MSR_KERNEL_GS_BASE;

		msrs[n++].index = MSR_SYSCALL_MASK;
		msrs[n++].index = MSR_LSTAR;
#endif

		/*
		 * The following paravirtual MSRs have side effects on the guest or are
		 * too heavy for normal writeback. Limit them to reset or full state
		 * updates.
		 */

		/* Do we need to reset time? */
		/*
		 * KVM is yet unable to synchronize TSC values of multiple VCPUs on
		 * writeback. Until this is fixed, we only write the offset to SMP
		 * guests after migration, desynchronizing the VCPUs, but avoiding
		 * huge jump-backs that would occur without any writeback at all.
		 */

		/*same as MSR_KVM_WALL_CLOCK_NEW. Use that instead.
		 *The hypervisor is only guaranteed to update this data at the moment of MSR write.
		 *Note that although MSRs are per-CPU entities, the effect of this particular MSR is global.
		 */
		/* rsr-debug just for debugging
		 * msrs[n++].index = MSR_KVM_WALL_CLOCK_NEW;
		 * same as MSR_KVM_SYSTEM_TIME_NEW. Use that instead.
		 * msrs[n++].index = MSR_KVM_SYSTEM_TIME_NEW;
		 */
		if (kvm_has_feature(KVM_FEATURE_ASYNC_PF)) {
			msrs[n++].index = MSR_KVM_ASYNC_PF_EN;
		}
		if (kvm_has_feature(KVM_FEATURE_PV_EOI)) {
			msrs[n++].index = MSR_KVM_PV_EOI_EN;
		}

		mcg_cap = vcpu->arch.mcg_cap;	//need to confirm!!!

#ifdef KVM_CAP_MCE
		msrs[n++].index = MSR_IA32_MCG_STATUS;
		msrs[n++].index = MSR_IA32_MCG_CTL;
		for (i = 0; i < (mcg_cap & 0xff) * 4; i++) {
			msrs[n++].index = MSR_IA32_MC0_CTL + i;
		}
#endif
		//rsr-debug
		//BUG FIX: need to calculate the number of the msrs
		msr_data->info.nmsrs = n;
		//end rsr-debug
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu,
				set ? KVM_SET_MSRS : KVM_GET_MSRS, msr_data);
	return ret;
}

int kvm_arch_getset_registers(struct kvm_vcpu *vcpu, int set)
{
	int ret;
	struct rr_CPUX86State *env = &(vcpu->rr_info.vcpu_checkpoint);

	ret = kvm_getset_regs(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_xsave(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_xcrs(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_sregs(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}

	/* Set_sregs lead to destroy mmu which will be used in set_msrs,
	 * so reload it before set_msrs.
	 */
	ret = kvm_mmu_reload(vcpu);
	if (unlikely(ret)) {
		RR_DLOG(ERR, "error: vcpu=%d fial to kvm_mmu_reload()",
			vcpu->vcpu_id);
		return -1;
	}
	ret = kvm_getset_msrs(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_mp_state(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_apic(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_vcpu_events(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_debugregs(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	return 0;
}

void print_vcpu_status_info_for_debugging(struct rr_CPUX86State *env)
{
	int i = 0, j = 0;
	struct kvm_regs *kvm_regs = &env->kvm_regs;
	struct kvm_fpu *fpu = &env->fpu;

	printk("------------------standard registers-----------------\n");
	printk("rax: %llx\n", kvm_regs->rax);
	printk("rbx: %llx\n", kvm_regs->rbx);
	printk("rcx: %llx\n", kvm_regs->rcx);
	printk("rdx: %llx\n", kvm_regs->rdx);
	printk("rsi: %llx\n", kvm_regs->rsi);
	printk("rdi: %llx\n", kvm_regs->rdi);
	printk("rsp: %llx\n", kvm_regs->rsp);
	printk("rbp: %llx\n", kvm_regs->rbp);

	printk("r8: %llx\n", kvm_regs->r8);
	printk("r9: %llx\n", kvm_regs->r9);
	printk("r10: %llx\n", kvm_regs->r10);
	printk("r11: %llx\n", kvm_regs->r11);
	printk("r12: %llx\n", kvm_regs->r12);
	printk("r13: %llx\n", kvm_regs->r13);
	printk("r14: %llx\n", kvm_regs->r14);
	printk("r15: %llx\n", kvm_regs->r15);
	printk("rip: %llx\n", kvm_regs->rip);
	printk("rflags: %llx\n", kvm_regs->rflags);

	printk("----------------------FPU state---------------------\n");
	for (i=0; i<8; i++) {
		for(j=0; j<16; j++){
			printk("fpr[%d][%d]=0x%x ", i, j, fpu->fpr[i][j]);
		}
		printk("\n");
	}
	printk("fcw: 0x%x\n", fpu->fcw);
	printk("fsw: 0x%x\n", fpu->fsw);
	printk("ftwx: 0x%x\n", fpu->ftwx);
	printk("pad1: 0x%x\n", fpu->pad1);
	printk("last_opcode: 0x%x\n", fpu->last_opcode);
	printk("last_ip: 0x%llx\n", fpu->last_ip);
	printk("last_dp: 0x%llx\n", fpu->last_dp);
	for (i=0; i<16; i++) {
		for(j=0; j<16; j++){
			printk("xmm[%d][%d]=0x%x ", i, j, fpu->xmm[i][j]);
		}
		printk("\n");
	}
	printk("mxcsr: 0x%x\n", fpu->mxcsr);
	printk("pad2: 0x%x\n", fpu->pad2);

	printk("------------------------XSAVE---------------------\n");
	for(j=0; j<1024; j++){
		printk("region[%d]=0x%x ", j, env->xsave.region[i]);
	}
	printk("\n");
}

int rr_do_vcpu_checkpoint(struct kvm_vcpu *vcpu)
{
	int ret = kvm_arch_getset_registers(vcpu, 0);

	if ( ret < 0 ){
		RR_DLOG(ERR,
			"error: vcpu=%d fail to kvm_arch_getset_registers()",
			vcpu->vcpu_id);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(rr_do_vcpu_checkpoint);

int rr_do_vcpu_rollback(struct kvm_vcpu *vcpu)
{
	int ret = kvm_arch_getset_registers(vcpu, 1);

	if ( ret < 0 ){
		RR_DLOG(ERR,
			"error: vcpu=%d fail to kvm_arch_getset_registers()",
			vcpu->vcpu_id);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(rr_do_vcpu_rollback);
