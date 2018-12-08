static int CVE_2011_2535_VULN_iax2_setoption(struct ast_channel *c, int option, void *data, int datalen)
{
	struct ast_option_header *h;
	int res;

	switch (option) {
	case AST_OPTION_TXGAIN:
	case AST_OPTION_RXGAIN:
		/* these two cannot be sent, because they require a result */
		errno = ENOSYS;
		return -1;
	case AST_OPTION_FORMAT_READ:
	case AST_OPTION_FORMAT_WRITE:
	case AST_OPTION_MAKE_COMPATIBLE:
		return -1;
	case AST_OPTION_OPRMODE:
		errno = EINVAL;
		return -1;
	case AST_OPTION_SECURE_SIGNALING:
	case AST_OPTION_SECURE_MEDIA:
	{
		unsigned short callno = PTR_TO_CALLNO(c->tech_pvt);
		ast_mutex_lock(&iaxsl[callno]);
		if ((*(int *) data)) {
			ast_set_flag64(iaxs[callno], IAX_FORCE_ENCRYPT);
		} else {
			ast_clear_flag64(iaxs[callno], IAX_FORCE_ENCRYPT);
		}
		ast_mutex_unlock(&iaxsl[callno]);
		return 0;
	}
	default:
	{
		unsigned short callno = PTR_TO_CALLNO(c->tech_pvt);
		struct chan_iax2_pvt *pvt;

		ast_mutex_lock(&iaxsl[callno]);
		pvt = iaxs[callno];

		if (wait_for_peercallno(pvt)) {
			ast_mutex_unlock(&iaxsl[callno]);
			return -1;
		}

		ast_mutex_unlock(&iaxsl[callno]);

		if (!(h = ast_malloc(datalen + sizeof(*h)))) {
			return -1;
		}

		h->flag = AST_OPTION_FLAG_REQUEST;
		h->option = htons(option);
		memcpy(h->data, data, datalen);
		res = send_command_locked(PTR_TO_CALLNO(c->tech_pvt), AST_FRAME_CONTROL,
					  AST_CONTROL_OPTION, 0, (unsigned char *) h,
					  datalen + sizeof(*h), -1);
		ast_free(h);
		return res;
	}
	}
}
