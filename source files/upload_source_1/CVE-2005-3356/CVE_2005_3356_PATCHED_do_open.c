static struct file *CVE_2005_3356_PATCHED_do_open(struct dentry *dentry, int oflag)
{
static int oflag2acc[O_ACCMODE] = { MAY_READ, MAY_WRITE,
					MAY_READ | MAY_WRITE };

	if ((oflag & O_ACCMODE) == (O_RDWR | O_WRONLY)) {
		dput(dentry);
		mntput(mqueue_mnt);
		return ERR_PTR(-EINVAL);
	}

	if (permission(dentry->d_inode, oflag2acc[oflag & O_ACCMODE], NULL)) {
		dput(dentry);
		mntput(mqueue_mnt);
		return ERR_PTR(-EACCES);
	}

	return dentry_open(dentry, mqueue_mnt, oflag);
}
