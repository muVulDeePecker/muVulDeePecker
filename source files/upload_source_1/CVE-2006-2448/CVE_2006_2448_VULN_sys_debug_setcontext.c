int CVE_2006_2448_VULN_sys_debug_setcontext(struct ucontext __user *ctx,
			 int ndbg, struct sig_dbg_op __user *dbg,
			 int r6, int r7, int r8,
			 struct pt_regs *regs)
{
	struct sig_dbg_op op;
	int i;
	unsigned long new_msr = regs->msr;
#if defined(CONFIG_4xx) || defined(CONFIG_BOOKE)
	unsigned long new_dbcr0 = current->thread.dbcr0;
#endif

	for (i=0; i<ndbg; i++) {
		if (__copy_from_user(&op, dbg, sizeof(op)))
			return -EFAULT;
		switch (op.dbg_type) {
		case SIG_DBG_SINGLE_STEPPING:
#if defined(CONFIG_4xx) || defined(CONFIG_BOOKE)
			if (op.dbg_value) {
				new_msr |= MSR_DE;
				new_dbcr0 |= (DBCR0_IDM | DBCR0_IC);
			} else {
				new_msr &= ~MSR_DE;
				new_dbcr0 &= ~(DBCR0_IDM | DBCR0_IC);
			}
#else
			if (op.dbg_value)
				new_msr |= MSR_SE;
			else
				new_msr &= ~MSR_SE;
#endif
			break;
		case SIG_DBG_BRANCH_TRACING:
#if defined(CONFIG_4xx) || defined(CONFIG_BOOKE)
			return -EINVAL;
#else
			if (op.dbg_value)
				new_msr |= MSR_BE;
			else
				new_msr &= ~MSR_BE;
#endif
			break;

		default:
			return -EINVAL;
		}
	}

	/* We wait until here to actually install the values in the
	   registers so if we fail in the above loop, it will not
	   affect the contents of these registers.  After this point,
	   failure is a problem, anyway, and it's very unlikely unless
	   the user is really doing something wrong. */
	regs->msr = new_msr;
#if defined(CONFIG_4xx) || defined(CONFIG_BOOKE)
	current->thread.dbcr0 = new_dbcr0;
#endif

	/*
	 * If we get a fault copying the context into the kernel's
	 * image of the user's registers, we can't just return -EFAULT
	 * because the user's registers will be corrupted.  For instance
	 * the NIP value may have been updated but not some of the
	 * other registers.  Given that we have done the access_ok
	 * and successfully read the first and last bytes of the region
	 * above, this should only happen in an out-of-memory situation
	 * or if another thread unmaps the region containing the context.
	 * We kill the task with a SIGSEGV in this situation.
	 */
	if (do_setcontext(ctx, regs, 1)) {
		force_sig(SIGSEGV, current);
		goto out;
	}

	/*
	 * It's not clear whether or why it is desirable to save the
	 * sigaltstack setting on signal delivery and restore it on
	 * signal return.  But other architectures do this and we have
	 * always done it up until now so it is probably better not to
	 * change it.  -- paulus
	 */
	do_sigaltstack(&ctx->uc_stack, NULL, regs->gpr[1]);

	set_thread_flag(TIF_RESTOREALL);
 out:
	return 0;
}
