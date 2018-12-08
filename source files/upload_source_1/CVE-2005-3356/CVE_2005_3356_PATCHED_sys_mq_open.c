asmlinkage long CVE_2005_3356_PATCHED_sys_mq_open(const char __user *u_name, int oflag, mode_t mode,
				struct mq_attr __user *u_attr)
{
	struct dentry *dentry;
	struct file *filp;
	char *name;
	int fd, error;

	if (IS_ERR(name = getname(u_name)))
		return PTR_ERR(name);

	fd = get_unused_fd();
	if (fd < 0)
		goto out_putname;

	down(&mqueue_mnt->mnt_root->d_inode->i_sem);
	dentry = lookup_one_len(name, mqueue_mnt->mnt_root, strlen(name));
	if (IS_ERR(dentry)) {
		error = PTR_ERR(dentry);
		goto out_err;
	}
	mntget(mqueue_mnt);

	if (oflag & O_CREAT) {
		if (dentry->d_inode) {	/* entry already exists */
			error = -EEXIST;
			if (oflag & O_EXCL)
				goto out;
			filp = do_open(dentry, oflag);
		} else {
			filp = do_create(mqueue_mnt->mnt_root, dentry,
						oflag, mode, u_attr);
		}
	} else {
		error = -ENOENT;
		if (!dentry->d_inode)
			goto out;
		filp = do_open(dentry, oflag);
	}

	if (IS_ERR(filp)) {
		error = PTR_ERR(filp);
		goto out_putfd;
	}

	set_close_on_exec(fd, 1);
	fd_install(fd, filp);
	goto out_upsem;

out:
	dput(dentry);
	mntput(mqueue_mnt);
out_putfd:
	put_unused_fd(fd);
out_err:
	fd = error;
out_upsem:
	up(&mqueue_mnt->mnt_root->d_inode->i_sem);
out_putname:
	putname(name);
	return fd;
}
