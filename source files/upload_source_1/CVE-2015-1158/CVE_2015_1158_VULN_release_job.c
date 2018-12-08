 */

static void
CVE_2015_1158_VULN_release_job(cupsd_client_t  *con,	/* I - Client connection */
            ipp_attribute_t *uri)	/* I - Job or Printer URI */
{
  ipp_attribute_t *attr;		/* Current attribute */
  int		jobid;			/* Job ID */
  char		scheme[HTTP_MAX_URI],	/* Method portion of URI */
		username[HTTP_MAX_URI],	/* Username portion of URI */
		host[HTTP_MAX_URI],	/* Host portion of URI */
		resource[HTTP_MAX_URI];	/* Resource portion of URI */
  int		port;			/* Port portion of URI */
  cupsd_job_t	*job;			/* Job information */


  cupsdLogMessage(CUPSD_LOG_DEBUG2, "CVE_2015_1158_VULN_release_job(%p[%d], %s)", con,
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

 /*
  * See if job is "held"...
  */

  if (job->state_value != IPP_JOB_HELD)
  {
   /*
    * Nope - return a "not possible" error...
    */

    send_ipp_status(con, IPP_NOT_POSSIBLE, _("Job #%d is not held."), jobid);
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
  * Reset the job-hold-until value to "no-hold"...
  */

  if ((attr = ippFindAttribute(job->attrs, "job-hold-until",
                               IPP_TAG_KEYWORD)) == NULL)
    attr = ippFindAttribute(job->attrs, "job-hold-until", IPP_TAG_NAME);

  if (attr)
  {
    _cupsStrFree(attr->values[0].string.text);

    attr->value_tag = IPP_TAG_KEYWORD;
    attr->values[0].string.text = _cupsStrAlloc("no-hold");

    cupsdAddEvent(CUPSD_EVENT_JOB_CONFIG_CHANGED, cupsdFindDest(job->dest), job,
                  "Job job-hold-until value changed by user.");
    ippSetString(job->attrs, &job->reasons, 0, "none");
  }

 /*
  * Release the job and return...
  */

  cupsdReleaseJob(job);

  cupsdAddEvent(CUPSD_EVENT_JOB_STATE, cupsdFindDest(job->dest), job,
                "Job released by user.");

  cupsdLogJob(job, CUPSD_LOG_INFO, "Released by \"%s\".", username);

  con->response->request.status.status_code = IPP_OK;

  cupsdCheckJobs();
}
