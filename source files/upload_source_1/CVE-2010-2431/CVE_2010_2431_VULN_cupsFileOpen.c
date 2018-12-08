 */

cups_file_t *				/* O - CUPS file or @code NULL@ if the file or socket cannot be opened */
CVE_2010_2431_VULN_cupsFileOpen(const char *filename,	/* I - Name of file */
             const char *mode)		/* I - Open mode */
{
  cups_file_t	*fp;			/* New CUPS file */
  int		fd;			/* File descriptor */
  char		hostname[1024],		/* Hostname */
		*portname;		/* Port "name" (number or service) */
  http_addrlist_t *addrlist;		/* Host address list */


  DEBUG_printf(("CVE_2010_2431_VULN_cupsFileOpen(filename=\"%s\", mode=\"%s\")", filename,
                mode));

 /*
  * Range check input...
  */

  if (!filename || !mode ||
      (*mode != 'r' && *mode != 'w' && *mode != 'a' && *mode != 's') ||
      (*mode == 'a' && isdigit(mode[1] & 255)))
    return (NULL);

 /*
  * Open the file...
  */

  switch (*mode)
  {
    case 'a' : /* Append file */
        fd = open(filename, O_RDWR | O_CREAT | O_APPEND | O_LARGEFILE | O_BINARY, 0666);
        break;

    case 'r' : /* Read file */
	fd = open(filename, O_RDONLY | O_LARGEFILE | O_BINARY, 0);
	break;

    case 'w' : /* Write file */
        fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT | O_LARGEFILE | O_BINARY, 0666);
        break;

    case 's' : /* Read/write socket */
        strlcpy(hostname, filename, sizeof(hostname));
	if ((portname = strrchr(hostname, ':')) != NULL)
	  *portname++ = '\0';
	else
	  return (NULL);

       /*
        * Lookup the hostname and service...
	*/

        if ((addrlist = httpAddrGetList(hostname, AF_UNSPEC, portname)) == NULL)
	  return (NULL);

       /*
	* Connect to the server...
	*/

        if (!httpAddrConnect(addrlist, &fd))
	{
	  httpAddrFreeList(addrlist);
	  return (NULL);
	}

	httpAddrFreeList(addrlist);
	break;

    default : /* Remove bogus compiler warning... */
        return (NULL);
  }

  if (fd < 0)
    return (NULL);

 /*
  * Create the CUPS file structure...
  */

  if ((fp = cupsFileOpenFd(fd, mode)) == NULL)
  {
    if (*mode == 's')
      closesocket(fd);
    else
      close(fd);
  }

 /*
  * Return it...
  */

  return (fp);
}
