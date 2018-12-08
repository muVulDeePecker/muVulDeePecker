static long CVE_2006_2448_VULN_restore_sigcontext(struct pt_regs *regs, sigset_t *set, int sig,
			      struct sigcontext __user *sc)
{
#ifdef CONFIG_ALTIVEC
	elf_vrreg_t __user *v_regs;
#endif
	unsigned long err = 0;
	unsigned long save_r13 = 0;
	elf_greg_t *gregs = (elf_greg_t *)regs;
#ifdef CONFIG_ALTIVEC
	unsigned long msr;
#endif
	int i;

	/* If this is not a signal return, we preserve the TLS in r13 */
	if (!sig)
		save_r13 = regs->gpr[13];

	/* copy everything before MSR */
	err |= __copy_from_user(regs, &sc->gp_regs,
				PT_MSR*sizeof(unsigned long));

	/* skip MSR and SOFTE */
	for (i = PT_MSR+1; i <= PT_RESULT; i++) {
		if (i == PT_SOFTE)
			continue;
		err |= __get_user(gregs[i], &sc->gp_regs[i]);
	}

	if (!sig)
		regs->gpr[13] = save_r13;
	if (set != NULL)
		err |=  __get_user(set->sig[0], &sc->oldmask);

	/*
	 * Do this before updating the thread state in
	 * current->thread.fpr/vr.  That way, if we get preempted
	 * and another task grabs the FPU/Altivec, it won't be
	 * tempted to save the current CPU state into the thread_struct
	 * and corrupt what we are writing there.
	 */
	discard_lazy_cpu_state();

	err |= __copy_from_user(&current->thread.fpr, &sc->fp_regs, FP_REGS_SIZE);

#ifdef CONFIG_ALTIVEC
	err |= __get_user(v_regs, &sc->v_regs);
	err |= __get_user(msr, &sc->gp_regs[PT_MSR]);
	if (err)
		return err;
	/* Copy 33 vec registers (vr0..31 and vscr) from the stack */
	if (v_regs != 0 && (msr & MSR_VEC) != 0)
		err |= __copy_from_user(current->thread.vr, v_regs,
					33 * sizeof(vector128));
	else if (current->thread.used_vr)
		memset(current->thread.vr, 0, 33 * sizeof(vector128));
	/* Always get VRSAVE back */
	if (v_regs != 0)
		err |= __get_user(current->thread.vrsave, (u32 __user *)&v_regs[33]);
	else
		current->thread.vrsave = 0;
#endif /* CONFIG_ALTIVEC */

	/* Force reload of FP/VEC */
	regs->msr &= ~(MSR_FP | MSR_FE0 | MSR_FE1 | MSR_VEC);

	return err;
}
