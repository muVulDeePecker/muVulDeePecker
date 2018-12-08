static long
CVE_2011_1495_VULN__ctl_diag_read_buffer(void __user *arg, enum block_state state)
{
	struct mpt2_diag_read_buffer karg;
	struct mpt2_diag_read_buffer __user *uarg = arg;
	struct MPT2SAS_ADAPTER *ioc;
	void *request_data, *diag_data;
	Mpi2DiagBufferPostRequest_t *mpi_request;
	Mpi2DiagBufferPostReply_t *mpi_reply;
	int rc, i;
	u8 buffer_type;
	unsigned long timeleft;
	u16 smid;
	u16 ioc_status;
	u8 issue_reset = 0;

	if (copy_from_user(&karg, arg, sizeof(karg))) {
		printk(KERN_ERR "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		return -EFAULT;
	}
	if (_ctl_verify_adapter(karg.hdr.ioc_number, &ioc) == -1 || !ioc)
		return -ENODEV;

	dctlprintk(ioc, printk(MPT2SAS_INFO_FMT "%s\n", ioc->name,
	    __func__));

	buffer_type = karg.unique_id & 0x000000ff;
	if (!_ctl_diag_capability(ioc, buffer_type)) {
		printk(MPT2SAS_ERR_FMT "%s: doesn't have capability for "
		    "buffer_type(0x%02x)\n", ioc->name, __func__, buffer_type);
		return -EPERM;
	}

	if (karg.unique_id != ioc->unique_id[buffer_type]) {
		printk(MPT2SAS_ERR_FMT "%s: unique_id(0x%08x) is not "
		    "registered\n", ioc->name, __func__, karg.unique_id);
		return -EINVAL;
	}

	request_data = ioc->diag_buffer[buffer_type];
	if (!request_data) {
		printk(MPT2SAS_ERR_FMT "%s: doesn't have buffer for "
		    "buffer_type(0x%02x)\n", ioc->name, __func__, buffer_type);
		return -ENOMEM;
	}

	if ((karg.starting_offset % 4) || (karg.bytes_to_read % 4)) {
		printk(MPT2SAS_ERR_FMT "%s: either the starting_offset "
		    "or bytes_to_read are not 4 byte aligned\n", ioc->name,
		    __func__);
		return -EINVAL;
	}

	diag_data = (void *)(request_data + karg.starting_offset);
	dctlprintk(ioc, printk(MPT2SAS_INFO_FMT "%s: diag_buffer(%p), "
	    "offset(%d), sz(%d)\n", ioc->name, __func__,
	    diag_data, karg.starting_offset, karg.bytes_to_read));

	if (copy_to_user((void __user *)uarg->diagnostic_data,
	    diag_data, karg.bytes_to_read)) {
		printk(MPT2SAS_ERR_FMT "%s: Unable to write "
		    "mpt_diag_read_buffer_t data @ %p\n", ioc->name,
		    __func__, diag_data);
		return -EFAULT;
	}

	if ((karg.flags & MPT2_FLAGS_REREGISTER) == 0)
		return 0;

	dctlprintk(ioc, printk(MPT2SAS_INFO_FMT "%s: Reregister "
		"buffer_type(0x%02x)\n", ioc->name, __func__, buffer_type));
	if ((ioc->diag_buffer_status[buffer_type] &
	    MPT2_DIAG_BUFFER_IS_RELEASED) == 0) {
		dctlprintk(ioc, printk(MPT2SAS_INFO_FMT "%s: "
		    "buffer_type(0x%02x) is still registered\n", ioc->name,
		     __func__, buffer_type));
		return 0;
	}
	/* Get a free request frame and save the message context.
	*/
	if (state == NON_BLOCKING && !mutex_trylock(&ioc->ctl_cmds.mutex))
		return -EAGAIN;
	else if (mutex_lock_interruptible(&ioc->ctl_cmds.mutex))
		return -ERESTARTSYS;

	if (ioc->ctl_cmds.status != MPT2_CMD_NOT_USED) {
		printk(MPT2SAS_ERR_FMT "%s: ctl_cmd in use\n",
		    ioc->name, __func__);
		rc = -EAGAIN;
		goto out;
	}

	smid = mpt2sas_base_get_smid(ioc, ioc->ctl_cb_idx);
	if (!smid) {
		printk(MPT2SAS_ERR_FMT "%s: failed obtaining a smid\n",
		    ioc->name, __func__);
		rc = -EAGAIN;
		goto out;
	}

	rc = 0;
	ioc->ctl_cmds.status = MPT2_CMD_PENDING;
	memset(ioc->ctl_cmds.reply, 0, ioc->reply_sz);
	mpi_request = mpt2sas_base_get_msg_frame(ioc, smid);
	ioc->ctl_cmds.smid = smid;

	mpi_request->Function = MPI2_FUNCTION_DIAG_BUFFER_POST;
	mpi_request->BufferType = buffer_type;
	mpi_request->BufferLength =
	    cpu_to_le32(ioc->diag_buffer_sz[buffer_type]);
	mpi_request->BufferAddress =
	    cpu_to_le64(ioc->diag_buffer_dma[buffer_type]);
	for (i = 0; i < MPT2_PRODUCT_SPECIFIC_DWORDS; i++)
		mpi_request->ProductSpecific[i] =
			cpu_to_le32(ioc->product_specific[buffer_type][i]);
	mpi_request->VF_ID = 0; /* TODO */
	mpi_request->VP_ID = 0;

	mpt2sas_base_put_smid_default(ioc, smid);
	init_completion(&ioc->ctl_cmds.done);
	timeleft = wait_for_completion_timeout(&ioc->ctl_cmds.done,
	    MPT2_IOCTL_DEFAULT_TIMEOUT*HZ);

	if (!(ioc->ctl_cmds.status & MPT2_CMD_COMPLETE)) {
		printk(MPT2SAS_ERR_FMT "%s: timeout\n", ioc->name,
		    __func__);
		_debug_dump_mf(mpi_request,
		    sizeof(Mpi2DiagBufferPostRequest_t)/4);
		if (!(ioc->ctl_cmds.status & MPT2_CMD_RESET))
			issue_reset = 1;
		goto issue_host_reset;
	}

	/* process the completed Reply Message Frame */
	if ((ioc->ctl_cmds.status & MPT2_CMD_REPLY_VALID) == 0) {
		printk(MPT2SAS_ERR_FMT "%s: no reply message\n",
		    ioc->name, __func__);
		rc = -EFAULT;
		goto out;
	}

	mpi_reply = ioc->ctl_cmds.reply;
	ioc_status = le16_to_cpu(mpi_reply->IOCStatus) & MPI2_IOCSTATUS_MASK;

	if (ioc_status == MPI2_IOCSTATUS_SUCCESS) {
		ioc->diag_buffer_status[buffer_type] |=
		    MPT2_DIAG_BUFFER_IS_REGISTERED;
		dctlprintk(ioc, printk(MPT2SAS_INFO_FMT "%s: success\n",
		    ioc->name, __func__));
	} else {
		printk(MPT2SAS_INFO_FMT "%s: ioc_status(0x%04x) "
		    "log_info(0x%08x)\n", ioc->name, __func__,
		    ioc_status, le32_to_cpu(mpi_reply->IOCLogInfo));
		rc = -EFAULT;
	}

 issue_host_reset:
	if (issue_reset)
		mpt2sas_base_hard_reset_handler(ioc, CAN_SLEEP,
		    FORCE_BIG_HAMMER);

 out:

	ioc->ctl_cmds.status = MPT2_CMD_NOT_USED;
	mutex_unlock(&ioc->ctl_cmds.mutex);
	return rc;
}
