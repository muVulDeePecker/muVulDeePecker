 */

static char *				/* O  - Real filename */
CVE_2014_3537_VULN_get_file(cupsd_client_t *con,		/* I  - Client connection */
         struct stat    *filestats,	/* O  - File information */
         char           *filename,	/* IO - Filename buffer */
         int            len)		/* I  - Buffer length */
{
  int		status;			/* Status of filesystem calls */
  char		*ptr;			/* Pointer info filename */
  int		plen;			/* Remaining length after pointer */
  char		language[7];		/* Language subdirectory, if any */


 /*
  * Figure out the real filename...
  */

  language[0] = '\0';

  if (!strncmp(con->uri, "/ppd/", 5))
    snprintf(filename, len, "%s%s", ServerRoot, con->uri);
  else if (!strncmp(con->uri, "/rss/", 5) && !strchr(con->uri + 5, '/'))
    snprintf(filename, len, "%s/rss/%s", CacheDir, con->uri + 5);
  else if (!strncmp(con->uri, "/admin/conf/", 12))
    snprintf(filename, len, "%s%s", ServerRoot, con->uri + 11);
  else if (!strncmp(con->uri, "/admin/log/", 11))
  {
    if (!strncmp(con->uri + 11, "access_log", 10) && AccessLog[0] == '/')
      strlcpy(filename, AccessLog, len);
    else if (!strncmp(con->uri + 11, "error_log", 9) && ErrorLog[0] == '/')
      strlcpy(filename, ErrorLog, len);
    else if (!strncmp(con->uri + 11, "page_log", 8) && PageLog[0] == '/')
      strlcpy(filename, PageLog, len);
    else
      return (NULL);
  }
  else if (con->language)
  {
    snprintf(language, sizeof(language), "/%s", con->language->language);
    snprintf(filename, len, "%s%s%s", DocumentRoot, language, con->uri);
  }
  else
    snprintf(filename, len, "%s%s", DocumentRoot, con->uri);

  if ((ptr = strchr(filename, '?')) != NULL)
    *ptr = '\0';

 /*
  * Grab the status for this language; if there isn't a language-specific file
  * then fallback to the default one...
  */

  if ((status = stat(filename, filestats)) != 0 && language[0] &&
      strncmp(con->uri, "/ppd/", 5) &&
      strncmp(con->uri, "/admin/conf/", 12) &&
      strncmp(con->uri, "/admin/log/", 11))
  {
   /*
    * Drop the country code...
    */

    language[3] = '\0';
    snprintf(filename, len, "%s%s%s", DocumentRoot, language, con->uri);

    if ((ptr = strchr(filename, '?')) != NULL)
      *ptr = '\0';

    if ((status = stat(filename, filestats)) != 0)
    {
     /*
      * Drop the language prefix and try the root directory...
      */

      language[0] = '\0';
      snprintf(filename, len, "%s%s", DocumentRoot, con->uri);

      if ((ptr = strchr(filename, '?')) != NULL)
	*ptr = '\0';

      status = stat(filename, filestats);
    }
  }

 /*
  * If we're found a directory, get the index.html file instead...
  */

  if (!status && S_ISDIR(filestats->st_mode))
  {
   /*
    * Make sure the URI ends with a slash...
    */

    if (con->uri[strlen(con->uri) - 1] != '/')
      strlcat(con->uri, "/", sizeof(con->uri));

   /*
    * Find the directory index file, trying every language...
    */

    do
    {
      if (status && language[0])
      {
       /*
        * Try a different language subset...
	*/

	if (language[3])
	  language[0] = '\0';		/* Strip country code */
	else
	  language[0] = '\0';		/* Strip language */
      }

     /*
      * Look for the index file...
      */

      snprintf(filename, len, "%s%s%s", DocumentRoot, language, con->uri);

      if ((ptr = strchr(filename, '?')) != NULL)
	*ptr = '\0';

      ptr  = filename + strlen(filename);
      plen = len - (ptr - filename);

      strlcpy(ptr, "index.html", plen);
      status = stat(filename, filestats);

#ifdef HAVE_JAVA
      if (status)
      {
	strlcpy(ptr, "index.class", plen);
	status = stat(filename, filestats);
      }
#endif /* HAVE_JAVA */

#ifdef HAVE_PERL
      if (status)
      {
	strlcpy(ptr, "index.pl", plen);
	status = stat(filename, filestats);
      }
#endif /* HAVE_PERL */

#ifdef HAVE_PHP
      if (status)
      {
	strlcpy(ptr, "index.php", plen);
	status = stat(filename, filestats);
      }
#endif /* HAVE_PHP */

#ifdef HAVE_PYTHON
      if (status)
      {
	strlcpy(ptr, "index.pyc", plen);
	status = stat(filename, filestats);
      }

      if (status)
      {
	strlcpy(ptr, "index.py", plen);
	status = stat(filename, filestats);
      }
#endif /* HAVE_PYTHON */

    }
    while (status && language[0]);
  }

  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "CVE_2014_3537_VULN_get_file(con=%p(%d), filestats=%p, filename=%p, len=%d) = "
		  "%s", con, con->http.fd, filestats, filename, len,
		  status ? "(null)" : filename);

  if (status)
    return (NULL);
  else
    return (filename);
}
