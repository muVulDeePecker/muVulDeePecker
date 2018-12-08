 */

static void
CVE_2015_1158_VULN_authenticate_job(cupsd_client_t  *con,	/* I - Client connection */
	         ipp_attribute_t *uri)	/* I - Job URI */
{
  ipp_attribute_t	*attr,		/* job-id attribute */
			*auth_info;	/* auth-info attribute */
  int			jobid;		/* Job ID */
  cupsd_job_t		*job;		/* Current job */
  char			scheme[HTTP_MAX_URI],
					/* Method portion of URI */
			username[HTTP_MAX_URI],
					/* Username portion of URI */
			host[HTTP_MAX_URI],
					/* Host portion of URI */
			resource[HTTP_MAX_URI];
					/* Resource portion of URI */
  int			port;		/* Port portion of URI */


  cupsdLogMessage(CUPSD_LOG_DEBUG2, "CVE_2015_1158_VULN_authenticate_job(%p[%d], %s)",
                  con, con->number, uri->values[0].string.text);

 /*
  * Start with "everything is OK" status...
  */

  con->response->request.status.status_code = IPP_OK;

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

 /*
  * See if the job has been completed...
  */

  if (job->state_value != IPP_JOB_HELD)
  {
   /*
    * Return a "not-possible" error...
    */

    send_ipp_status(con, IPP_NOT_POSSIBLE,
                    _("Job #%d is not held for authentication."),
		    jobid);
    return;
  }

 /*
  * See if we have already authenticated...
  */

  auth_info = ippFindAttribute(con->request, "auth-info", IPP_TAG_TEXT);

  if (!con->username[0] && !auth_info)
  {
    cupsd_printer_t	*printer;	/* Job destination */

   /*
    * No auth data.  If we need to authenticate via Kerberos, send a
    * HTTP auth challenge, otherwise just return an IPP error...
    */

    printer = cupsdFindDest(job->dest);

    if (printer && printer->num_auth_info_required > 0 &&
        !strcmp(printer->auth_info_required[0], "negotiate"))
      send_http_error(con, HTTP_UNAUTHORIZED, printer);
    else
      send_ipp_status(con, IPP_NOT_AUTHORIZED,
		      _("No authentication information provided."));
    return;
  }

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
  * Save the authentication information for this job...
  */

  save_auth_info(con, job, auth_info);

 /*
  * Reset the job-hold-until value to "no-hold"...
  */

  if ((attr = ippFindAttribute(job->attrs, "job-hold-until",
                               IPP_TAG_KEYWORD)) == NULL)
    attr = ippFindAttribute(job->attrs, "job-hold-until", IPP_TAG_NAME);

  if (attr)
  {
    attr->value_tag = IPP_TAG_KEYWORD;
    cupsdSetString(&(attr->values[0].string.text), "no-hold");
  }

 /*
  * Release the job and return...
  */

  cupsdReleaseJob(job);

  cupsdAddEvent(CUPSD_EVENT_JOB_STATE, NULL, job, "Job authenticated by user");

  cupsdLogJob(job, CUPSD_LOG_INFO, "Authenticated by \"%s\".", con->username);

  cupsdCheckJobs();
}
