 */

static void
CVE_2015_1158_VULN_send_document(cupsd_client_t  *con,	/* I - Client connection */
	      ipp_attribute_t *uri)	/* I - Printer URI */
{
  ipp_attribute_t	*attr;		/* Current attribute */
  ipp_attribute_t	*format;	/* Request's document-format attribute */
  ipp_attribute_t	*jformat;	/* Job's document-format attribute */
  const char		*default_format;/* document-format-default value */
  int			jobid;		/* Job ID number */
  cupsd_job_t		*job;		/* Current job */
  char			job_uri[HTTP_MAX_URI],
					/* Job URI */
			scheme[HTTP_MAX_URI],
					/* Method portion of URI */
			username[HTTP_MAX_URI],
					/* Username portion of URI */
			host[HTTP_MAX_URI],
					/* Host portion of URI */
			resource[HTTP_MAX_URI];
					/* Resource portion of URI */
  int			port;		/* Port portion of URI */
  mime_type_t		*filetype;	/* Type of file */
  char			super[MIME_MAX_SUPER],
					/* Supertype of file */
			type[MIME_MAX_TYPE],
					/* Subtype of file */
			mimetype[MIME_MAX_SUPER + MIME_MAX_TYPE + 2];
					/* Textual name of mime type */
  char			filename[1024];	/* Job filename */
  cupsd_printer_t	*printer;	/* Current printer */
  struct stat		fileinfo;	/* File information */
  int			kbytes;		/* Size of file */
  int			compression;	/* Type of compression */
  int			start_job;	/* Start the job? */


  cupsdLogMessage(CUPSD_LOG_DEBUG2, "CVE_2015_1158_VULN_send_document(%p[%d], %s)", con,
                  con->number, uri->values[0].string.text);

 /*
  * See if we have a job URI or a printer URI...
  */

  if (!strcmp(uri->name, "printer-uri"))
  {
   /*
    * Got a printer URI; see if we also have a job-id attribute...
    */

    if ((attr = ippFindAttribute(con->request, "job-id",
                                 IPP_TAG_INTEGER)) == NULL)
    {
      send_ipp_status(con, IPP_BAD_REQUEST,
                      _("Got a printer-uri attribute but no job-id."));
      return;
    }

    jobid = attr->values[0].integer;
  }
  else
  {
   /*
    * Got a job URI; parse it to get the job ID...
    */

    httpSeparateURI(HTTP_URI_CODING_ALL, uri->values[0].string.text, scheme,
                    sizeof(scheme), username, sizeof(username), host,
		    sizeof(host), &port, resource, sizeof(resource));

    if (strncmp(resource, "/jobs/", 6))
    {
     /*
      * Not a valid URI!
      */

      send_ipp_status(con, IPP_BAD_REQUEST, _("Bad job-uri \"%s\"."),
                      uri->values[0].string.text);
      return;
    }

    jobid = atoi(resource + 6);
  }

 /*
  * See if the job exists...
  */

  if ((job = cupsdFindJob(jobid)) == NULL)
  {
   /*
    * Nope - return a "not found" error...
    */

    send_ipp_status(con, IPP_NOT_FOUND, _("Job #%d does not exist."), jobid);
    return;
  }

  printer = cupsdFindDest(job->dest);

 /*
  * See if the job is owned by the requesting user...
  */

  if (!validate_user(job, con, job->username, username, sizeof(username)))
  {
    send_http_error(con, con->username[0] ? HTTP_FORBIDDEN : HTTP_UNAUTHORIZED,
                    cupsdFindDest(job->dest));
    return;
  }

 /*
  * OK, see if the client is sending the document compressed - CUPS
  * only supports "none" and "gzip".
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
      send_ipp_status(con, IPP_ATTRIBUTES, _("Unsupported compression \"%s\"."),
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

  if ((attr = ippFindAttribute(con->request, "last-document",
	                       IPP_TAG_BOOLEAN)) == NULL)
  {
    send_ipp_status(con, IPP_BAD_REQUEST,
                    _("Missing last-document attribute in request."));
    return;
  }

  if (!con->filename)
  {
   /*
    * Check for an empty request with "last-document" set to true, which is
    * used to close an "open" job by RFC 2911, section 3.3.2.
    */

    if (job->num_files > 0 && attr->values[0].boolean)
      goto last_document;

    send_ipp_status(con, IPP_BAD_REQUEST, _("No file in print request."));
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

    if (sscanf(format->values[0].string.text, "%15[^/]/%255[^;]",
               super, type) != 2)
    {
      send_ipp_status(con, IPP_BAD_REQUEST, _("Bad document-format \"%s\"."),
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
                      _("Bad document-format-default \"%s\"."), default_format);
      return;
    }
  }
  else
  {
   /*
    * No document format attribute?  Auto-type it!
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


    cupsdLogJob(job, CUPSD_LOG_DEBUG, "Auto-typing file...");

    doc_name = ippFindAttribute(con->request, "document-name", IPP_TAG_NAME);
    filetype = mimeFileType(MimeDatabase, con->filename,
                            doc_name ? doc_name->values[0].string.text : NULL,
			    &compression);

    if (!filetype)
      filetype = mimeType(MimeDatabase, super, type);

    if (filetype)
      cupsdLogJob(job, CUPSD_LOG_DEBUG, "Request file type is %s/%s.",
		  filetype->super, filetype->type);
  }
  else
    filetype = mimeType(MimeDatabase, super, type);

  if (filetype)
  {
   /*
    * Replace the document-format attribute value with the auto-typed or
    * default one.
    */

    snprintf(mimetype, sizeof(mimetype), "%s/%s", filetype->super,
             filetype->type);

    if ((jformat = ippFindAttribute(job->attrs, "document-format",
                                    IPP_TAG_MIMETYPE)) != NULL)
    {
      _cupsStrFree(jformat->values[0].string.text);

      jformat->values[0].string.text = _cupsStrAlloc(mimetype);
    }
    else
      ippAddString(job->attrs, IPP_TAG_JOB, IPP_TAG_MIMETYPE,
	           "document-format", NULL, mimetype);
  }
  else if (!filetype)
  {
    send_ipp_status(con, IPP_DOCUMENT_FORMAT,
                    _("Unsupported document-format \"%s/%s\"."), super, type);
    cupsdLogMessage(CUPSD_LOG_INFO,
                    "Hint: Do you have the raw file printing rules enabled?");

    if (format)
      ippAddString(con->response, IPP_TAG_UNSUPPORTED_GROUP, IPP_TAG_MIMETYPE,
                   "document-format", NULL, format->values[0].string.text);

    return;
  }

  if (printer->filetypes && !cupsArrayFind(printer->filetypes, filetype))
  {
    snprintf(mimetype, sizeof(mimetype), "%s/%s", filetype->super,
             filetype->type);

    send_ipp_status(con, IPP_DOCUMENT_FORMAT,
                    _("Unsupported document-format \"%s\"."), mimetype);

    ippAddString(con->response, IPP_TAG_UNSUPPORTED_GROUP, IPP_TAG_MIMETYPE,
                 "document-format", NULL, mimetype);

    return;
  }

 /*
  * Add the file to the job...
  */

  cupsdLoadJob(job);

  if (add_file(con, job, filetype, compression))
    return;

  if (stat(con->filename, &fileinfo))
    kbytes = 0;
  else
    kbytes = (fileinfo.st_size + 1023) / 1024;

  cupsdUpdateQuota(printer, job->username, 0, kbytes);

  job->koctets += kbytes;

  if ((attr = ippFindAttribute(job->attrs, "job-k-octets", IPP_TAG_INTEGER)) != NULL)
    attr->values[0].integer += kbytes;

  snprintf(filename, sizeof(filename), "%s/d%05d-%03d", RequestRoot, job->id,
           job->num_files);
  rename(con->filename, filename);

  cupsdClearString(&con->filename);

  cupsdLogJob(job, CUPSD_LOG_INFO, "File of type %s/%s queued by \"%s\".",
	      filetype->super, filetype->type, job->username);

 /*
  * Start the job if this is the last document...
  */

  last_document:

  if ((attr = ippFindAttribute(con->request, "last-document",
                               IPP_TAG_BOOLEAN)) != NULL &&
      attr->values[0].boolean)
  {
   /*
    * See if we need to add the ending sheet...
    */

    if (cupsdTimeoutJob(job))
      return;

    if (job->state_value == IPP_JOB_STOPPED)
    {
      job->state->values[0].integer = IPP_JOB_PENDING;
      job->state_value              = IPP_JOB_PENDING;

      ippSetString(job->attrs, &job->reasons, 0, "none");
    }
    else if (job->state_value == IPP_JOB_HELD)
    {
      if ((attr = ippFindAttribute(job->attrs, "job-hold-until",
                                   IPP_TAG_KEYWORD)) == NULL)
	attr = ippFindAttribute(job->attrs, "job-hold-until", IPP_TAG_NAME);

      if (!attr || !strcmp(attr->values[0].string.text, "no-hold"))
      {
	job->state->values[0].integer = IPP_JOB_PENDING;
	job->state_value              = IPP_JOB_PENDING;

	ippSetString(job->attrs, &job->reasons, 0, "none");
      }
      else
	ippSetString(job->attrs, &job->reasons, 0, "job-hold-until-specified");
    }

    job->dirty = 1;
    cupsdMarkDirty(CUPSD_DIRTY_JOBS);

    start_job = 1;
  }
  else
  {
    if ((attr = ippFindAttribute(job->attrs, "job-hold-until",
                                 IPP_TAG_KEYWORD)) == NULL)
      attr = ippFindAttribute(job->attrs, "job-hold-until", IPP_TAG_NAME);

    if (!attr || !strcmp(attr->values[0].string.text, "no-hold"))
    {
      job->state->values[0].integer = IPP_JOB_HELD;
      job->state_value              = IPP_JOB_HELD;
      job->hold_until               = time(NULL) + MultipleOperationTimeout;

      ippSetString(job->attrs, &job->reasons, 0, "job-incoming");

      job->dirty = 1;
      cupsdMarkDirty(CUPSD_DIRTY_JOBS);
    }

    start_job = 0;
  }

 /*
  * Fill in the response info...
  */

  httpAssembleURIf(HTTP_URI_CODING_ALL, job_uri, sizeof(job_uri), "ipp", NULL,
                   con->clientname, con->clientport, "/jobs/%d", jobid);
  ippAddString(con->response, IPP_TAG_JOB, IPP_TAG_URI, "job-uri", NULL,
               job_uri);

  ippAddInteger(con->response, IPP_TAG_JOB, IPP_TAG_INTEGER, "job-id", jobid);

  ippAddInteger(con->response, IPP_TAG_JOB, IPP_TAG_ENUM, "job-state",
                job->state_value);
  ippAddString(con->response, IPP_TAG_JOB, IPP_TAG_KEYWORD, "job-state-reasons",
               NULL, job->reasons->values[0].string.text);

  con->response->request.status.status_code = IPP_OK;

 /*
  * Start the job if necessary...
  */

  if (start_job)
    cupsdCheckJobs();
}
