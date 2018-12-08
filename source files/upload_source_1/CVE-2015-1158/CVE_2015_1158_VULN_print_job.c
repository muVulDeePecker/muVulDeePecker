 */

static void
CVE_2015_1158_VULN_print_job(cupsd_client_t  *con,		/* I - Client connection */
	  ipp_attribute_t *uri)		/* I - Printer URI */
{
  ipp_attribute_t *attr;		/* Current attribute */
  ipp_attribute_t *format;		/* Document-format attribute */
  const char	*default_format;	/* document-format-default value */
  cupsd_job_t	*job;			/* New job */
  char		filename[1024];		/* Job filename */
  mime_type_t	*filetype;		/* Type of file */
  char		super[MIME_MAX_SUPER],	/* Supertype of file */
		type[MIME_MAX_TYPE],	/* Subtype of file */
		mimetype[MIME_MAX_SUPER + MIME_MAX_TYPE + 2];
					/* Textual name of mime type */
  cupsd_printer_t *printer;		/* Printer data */
  struct stat	fileinfo;		/* File information */
  int		kbytes;			/* Size of file */
  int		compression;		/* Document compression */


  cupsdLogMessage(CUPSD_LOG_DEBUG2, "CVE_2015_1158_VULN_print_job(%p[%d], %s)", con, con->number,
                  uri->values[0].string.text);

 /*
  * Validate print file attributes, for now just document-format and
  * compression (CUPS only supports "none" and "gzip")...
  */

  compression = CUPS_FILE_NONE;

  if ((attr = ippFindAttribute(con->request, "compression",
                               IPP_TAG_KEYWORD)) != NULL)
  {
    if (strcmp(attr->values[0].string.text, "none")
#ifdef HAVE_LIBZ
        && strcmp(attr->values[0].string.text, "gzip")
#endif /* HAVE_LIBZ */
      )
    {
      send_ipp_status(con, IPP_ATTRIBUTES,
                      _("Unsupported compression \"%s\"."),
        	      attr->values[0].string.text);
      ippAddString(con->response, IPP_TAG_UNSUPPORTED_GROUP, IPP_TAG_KEYWORD,
	           "compression", NULL, attr->values[0].string.text);
      return;
    }

#ifdef HAVE_LIBZ
    if (!strcmp(attr->values[0].string.text, "gzip"))
      compression = CUPS_FILE_GZIP;
#endif /* HAVE_LIBZ */
  }

 /*
  * Do we have a file to print?
  */

  if (!con->filename)
  {
    send_ipp_status(con, IPP_BAD_REQUEST, _("No file in print request."));
    return;
  }

 /*
  * Is the destination valid?
  */

  if (!cupsdValidateDest(uri->values[0].string.text, NULL, &printer))
  {
   /*
    * Bad URI...
    */

    send_ipp_status(con, IPP_NOT_FOUND,
                    _("The printer or class does not exist."));
    return;
  }

 /*
  * Is it a format we support?
  */

  if ((format = ippFindAttribute(con->request, "document-format",
                                 IPP_TAG_MIMETYPE)) != NULL)
  {
   /*
    * Grab format from client...
    */

    if (sscanf(format->values[0].string.text, "%15[^/]/%255[^;]", super,
               type) != 2)
    {
      send_ipp_status(con, IPP_BAD_REQUEST,
                      _("Bad document-format \"%s\"."),
		      format->values[0].string.text);
      return;
    }
  }
  else if ((default_format = cupsGetOption("document-format",
                                           printer->num_options,
					   printer->options)) != NULL)
  {
   /*
    * Use default document format...
    */

    if (sscanf(default_format, "%15[^/]/%255[^;]", super, type) != 2)
    {
      send_ipp_status(con, IPP_BAD_REQUEST,
                      _("Bad document-format \"%s\"."),
		      default_format);
      return;
    }
  }
  else
  {
   /*
    * Auto-type it!
    */

    strlcpy(super, "application", sizeof(super));
    strlcpy(type, "octet-stream", sizeof(type));
  }

  if (!strcmp(super, "application") && !strcmp(type, "octet-stream"))
  {
   /*
    * Auto-type the file...
    */

    ipp_attribute_t	*doc_name;	/* document-name attribute */


    cupsdLogMessage(CUPSD_LOG_DEBUG, "[Job ???] Auto-typing file...");

    doc_name = ippFindAttribute(con->request, "document-name", IPP_TAG_NAME);
    filetype = mimeFileType(MimeDatabase, con->filename,
                            doc_name ? doc_name->values[0].string.text : NULL,
			    &compression);

    if (!filetype)
      filetype = mimeType(MimeDatabase, super, type);

    cupsdLogMessage(CUPSD_LOG_INFO, "[Job ???] Request file type is %s/%s.",
		    filetype->super, filetype->type);
  }
  else
    filetype = mimeType(MimeDatabase, super, type);

  if (filetype &&
      (!format ||
       (!strcmp(super, "application") && !strcmp(type, "octet-stream"))))
  {
   /*
    * Replace the document-format attribute value with the auto-typed or
    * default one.
    */

    snprintf(mimetype, sizeof(mimetype), "%s/%s", filetype->super,
             filetype->type);

    if (format)
    {
      _cupsStrFree(format->values[0].string.text);

      format->values[0].string.text = _cupsStrAlloc(mimetype);
    }
    else
      ippAddString(con->request, IPP_TAG_JOB, IPP_TAG_MIMETYPE,
	           "document-format", NULL, mimetype);
  }
  else if (!filetype)
  {
    send_ipp_status(con, IPP_DOCUMENT_FORMAT,
                    _("Unsupported document-format \"%s\"."),
		    format ? format->values[0].string.text :
			     "application/octet-stream");
    cupsdLogMessage(CUPSD_LOG_INFO,
                    "Hint: Do you have the raw file printing rules enabled?");

    if (format)
      ippAddString(con->response, IPP_TAG_UNSUPPORTED_GROUP, IPP_TAG_MIMETYPE,
                   "document-format", NULL, format->values[0].string.text);

    return;
  }

 /*
  * Read any embedded job ticket info from PS files...
  */

  if (!_cups_strcasecmp(filetype->super, "application") &&
      (!_cups_strcasecmp(filetype->type, "postscript") ||
       !_cups_strcasecmp(filetype->type, "pdf")))
    read_job_ticket(con);

 /*
  * Create the job object...
  */

  if ((job = add_job(con, printer, filetype)) == NULL)
    return;

 /*
  * Update quota data...
  */

  if (stat(con->filename, &fileinfo))
    kbytes = 0;
  else
    kbytes = (fileinfo.st_size + 1023) / 1024;

  cupsdUpdateQuota(printer, job->username, 0, kbytes);

  job->koctets += kbytes;

  if ((attr = ippFindAttribute(job->attrs, "job-k-octets", IPP_TAG_INTEGER)) != NULL)
    attr->values[0].integer += kbytes;

 /*
  * Add the job file...
  */

  if (add_file(con, job, filetype, compression))
    return;

  snprintf(filename, sizeof(filename), "%s/d%05d-%03d", RequestRoot, job->id,
           job->num_files);
  rename(con->filename, filename);
  cupsdClearString(&con->filename);

 /*
  * See if we need to add the ending sheet...
  */

  if (cupsdTimeoutJob(job))
    return;

 /*
  * Log and save the job...
  */

  cupsdLogJob(job, CUPSD_LOG_INFO,
	      "File of type %s/%s queued by \"%s\".",
	      filetype->super, filetype->type, job->username);
  cupsdLogJob(job, CUPSD_LOG_DEBUG, "hold_until=%d", (int)job->hold_until);
  cupsdLogJob(job, CUPSD_LOG_INFO, "Queued on \"%s\" by \"%s\".",
	      job->dest, job->username);

 /*
  * Start the job if possible...
  */

  cupsdCheckJobs();
}
