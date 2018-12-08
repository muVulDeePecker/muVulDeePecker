 */

int					/* O - 1 on success, 0 on failure */
CVE_2015_1158_VULN_cupsdProcessIPPRequest(
    cupsd_client_t *con)		/* I - Client connection */
{
  ipp_tag_t		group;		/* Current group tag */
  ipp_attribute_t	*attr;		/* Current attribute */
  ipp_attribute_t	*charset;	/* Character set attribute */
  ipp_attribute_t	*language;	/* Language attribute */
  ipp_attribute_t	*uri = NULL;	/* Printer or job URI attribute */
  ipp_attribute_t	*username;	/* requesting-user-name attr */
  int			sub_id;		/* Subscription ID */


  cupsdLogMessage(CUPSD_LOG_DEBUG2,
                  "CVE_2015_1158_VULN_cupsdProcessIPPRequest(%p[%d]): operation_id = %04x",
                  con, con->number, con->request->request.op.operation_id);

 /*
  * First build an empty response message for this request...
  */

  con->response = ippNew();

  con->response->request.status.version[0] =
      con->request->request.op.version[0];
  con->response->request.status.version[1] =
      con->request->request.op.version[1];
  con->response->request.status.request_id =
      con->request->request.op.request_id;

 /*
  * Then validate the request header and required attributes...
  */

  if (con->request->request.any.version[0] != 1 &&
      con->request->request.any.version[0] != 2)
  {
   /*
    * Return an error, since we only support IPP 1.x and 2.x.
    */

    cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                  "%04X %s Bad request version number %d.%d",
		  IPP_VERSION_NOT_SUPPORTED, con->http->hostname,
                  con->request->request.any.version[0],
	          con->request->request.any.version[1]);

    send_ipp_status(con, IPP_VERSION_NOT_SUPPORTED,
                    _("Bad request version number %d.%d."),
		    con->request->request.any.version[0],
	            con->request->request.any.version[1]);
  }
  else if (con->request->request.any.request_id < 1)
  {
   /*
    * Return an error, since request IDs must be between 1 and 2^31-1
    */

    cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                  "%04X %s Bad request ID %d",
		  IPP_BAD_REQUEST, con->http->hostname,
                  con->request->request.any.request_id);

    send_ipp_status(con, IPP_BAD_REQUEST, _("Bad request ID %d."),
		    con->request->request.any.request_id);
  }
  else if (!con->request->attrs)
  {
    cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                  "%04X %s No attributes in request",
		  IPP_BAD_REQUEST, con->http->hostname);

    send_ipp_status(con, IPP_BAD_REQUEST, _("No attributes in request."));
  }
  else
  {
   /*
    * Make sure that the attributes are provided in the correct order and
    * don't repeat groups...
    */

    for (attr = con->request->attrs, group = attr->group_tag;
	 attr;
	 attr = attr->next)
      if (attr->group_tag < group && attr->group_tag != IPP_TAG_ZERO)
      {
       /*
	* Out of order; return an error...
	*/

	cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                      "%04X %s Attribute groups are out of order",
		      IPP_BAD_REQUEST, con->http->hostname);

	send_ipp_status(con, IPP_BAD_REQUEST,
	                _("Attribute groups are out of order (%x < %x)."),
			attr->group_tag, group);
	break;
      }
      else
	group = attr->group_tag;

    if (!attr)
    {
     /*
      * Then make sure that the first three attributes are:
      *
      *     attributes-charset
      *     attributes-natural-language
      *     printer-uri/job-uri
      */

      attr = con->request->attrs;
      if (attr && attr->name &&
          !strcmp(attr->name, "attributes-charset") &&
	  (attr->value_tag & IPP_TAG_MASK) == IPP_TAG_CHARSET)
	charset = attr;
      else
	charset = NULL;

      if (attr)
        attr = attr->next;

      if (attr && attr->name &&
          !strcmp(attr->name, "attributes-natural-language") &&
	  (attr->value_tag & IPP_TAG_MASK) == IPP_TAG_LANGUAGE)
      {
	language = attr;

       /*
        * Reset language for this request if different from Accept-Language.
        */

	if (!con->language ||
	    strcmp(attr->values[0].string.text, con->language->language))
	{
	  cupsLangFree(con->language);
	  con->language = cupsLangGet(attr->values[0].string.text);
	}
      }
      else
	language = NULL;

      if ((attr = ippFindAttribute(con->request, "printer-uri",
                                   IPP_TAG_URI)) != NULL)
	uri = attr;
      else if ((attr = ippFindAttribute(con->request, "job-uri",
                                        IPP_TAG_URI)) != NULL)
	uri = attr;
      else if (con->request->request.op.operation_id == CUPS_GET_PPD)
        uri = ippFindAttribute(con->request, "ppd-name", IPP_TAG_NAME);
      else
	uri = NULL;

      if (charset)
	ippAddString(con->response, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL,
		     charset->values[0].string.text);
      else
	ippAddString(con->response, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL, "utf-8");

      if (language)
	ippAddString(con->response, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
                     "attributes-natural-language", NULL,
		     language->values[0].string.text);
      else
	ippAddString(con->response, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
                     "attributes-natural-language", NULL, DefaultLanguage);

      if (charset &&
          _cups_strcasecmp(charset->values[0].string.text, "us-ascii") &&
          _cups_strcasecmp(charset->values[0].string.text, "utf-8"))
      {
       /*
        * Bad character set...
	*/

        cupsdLogMessage(CUPSD_LOG_ERROR, "Unsupported character set \"%s\"",
	                charset->values[0].string.text);
	cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
		      "%04X %s Unsupported attributes-charset value \"%s\"",
		      IPP_CHARSET, con->http->hostname,
		      charset->values[0].string.text);
	send_ipp_status(con, IPP_BAD_REQUEST,
	                _("Unsupported character set \"%s\"."),
	                charset->values[0].string.text);
      }
      else if (!charset || !language ||
	       (!uri &&
	        con->request->request.op.operation_id != CUPS_GET_DEFAULT &&
	        con->request->request.op.operation_id != CUPS_GET_PRINTERS &&
	        con->request->request.op.operation_id != CUPS_GET_CLASSES &&
	        con->request->request.op.operation_id != CUPS_GET_DEVICES &&
	        con->request->request.op.operation_id != CUPS_GET_PPDS))
      {
       /*
	* Return an error, since attributes-charset,
	* attributes-natural-language, and printer-uri/job-uri are required
	* for all operations.
	*/

        if (!charset)
	{
	  cupsdLogMessage(CUPSD_LOG_ERROR,
	                  "Missing attributes-charset attribute");

	  cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                	"%04X %s Missing attributes-charset attribute",
			IPP_BAD_REQUEST, con->http->hostname);
        }

        if (!language)
	{
	  cupsdLogMessage(CUPSD_LOG_ERROR,
	                  "Missing attributes-natural-language attribute");

	  cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                	"%04X %s Missing attributes-natural-language attribute",
			IPP_BAD_REQUEST, con->http->hostname);
        }

        if (!uri)
	{
	  cupsdLogMessage(CUPSD_LOG_ERROR,
	                  "Missing printer-uri, job-uri, or ppd-name "
			  "attribute");

	  cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                	"%04X %s Missing printer-uri, job-uri, or ppd-name "
			"attribute", IPP_BAD_REQUEST, con->http->hostname);
        }

	cupsdLogMessage(CUPSD_LOG_DEBUG, "Request attributes follow...");

	for (attr = con->request->attrs; attr; attr = attr->next)
	  cupsdLogMessage(CUPSD_LOG_DEBUG,
	        	  "attr \"%s\": group_tag = %x, value_tag = %x",
	        	  attr->name ? attr->name : "(null)", attr->group_tag,
			  attr->value_tag);

	cupsdLogMessage(CUPSD_LOG_DEBUG, "End of attributes...");

	send_ipp_status(con, IPP_BAD_REQUEST,
	                _("Missing required attributes."));
      }
      else
      {
       /*
	* OK, all the checks pass so far; make sure requesting-user-name is
	* not "root" from a remote host...
	*/

        if ((username = ippFindAttribute(con->request, "requesting-user-name",
	                                 IPP_TAG_NAME)) != NULL)
	{
	 /*
	  * Check for root user...
	  */

	  if (!strcmp(username->values[0].string.text, "root") &&
	      _cups_strcasecmp(con->http->hostname, "localhost") &&
	      strcmp(con->username, "root"))
	  {
	   /*
	    * Remote unauthenticated user masquerading as local root...
	    */

	    _cupsStrFree(username->values[0].string.text);
	    username->values[0].string.text = _cupsStrAlloc(RemoteRoot);
	  }
	}

        if ((attr = ippFindAttribute(con->request, "notify-subscription-id",
	                             IPP_TAG_INTEGER)) != NULL)
	  sub_id = attr->values[0].integer;
	else
	  sub_id = 0;

       /*
        * Then try processing the operation...
	*/

        if (uri)
	  cupsdLogMessage(CUPSD_LOG_DEBUG, "%s %s",
                	  ippOpString(con->request->request.op.operation_id),
			  uri->values[0].string.text);
        else
	  cupsdLogMessage(CUPSD_LOG_DEBUG, "%s",
                	  ippOpString(con->request->request.op.operation_id));

	switch (con->request->request.op.operation_id)
	{
	  case IPP_OP_PRINT_JOB :
              print_job(con, uri);
              break;

	  case IPP_OP_VALIDATE_JOB :
              validate_job(con, uri);
              break;

	  case IPP_OP_CREATE_JOB :
              create_job(con, uri);
              break;

	  case IPP_OP_SEND_DOCUMENT :
              send_document(con, uri);
              break;

	  case IPP_OP_CANCEL_JOB :
              cancel_job(con, uri);
              break;

	  case IPP_OP_GET_JOB_ATTRIBUTES :
              get_job_attrs(con, uri);
              break;

	  case IPP_OP_GET_JOBS :
              get_jobs(con, uri);
              break;

	  case IPP_OP_GET_PRINTER_ATTRIBUTES :
              get_printer_attrs(con, uri);
              break;

	  case IPP_OP_GET_PRINTER_SUPPORTED_VALUES :
              get_printer_supported(con, uri);
              break;

	  case IPP_OP_HOLD_JOB :
              hold_job(con, uri);
              break;

	  case IPP_OP_RELEASE_JOB :
              release_job(con, uri);
              break;

	  case IPP_OP_RESTART_JOB :
              restart_job(con, uri);
              break;

	  case IPP_OP_PAUSE_PRINTER :
              stop_printer(con, uri);
	      break;

	  case IPP_OP_RESUME_PRINTER :
              start_printer(con, uri);
	      break;

	  case IPP_OP_PURGE_JOBS :
	  case IPP_OP_CANCEL_JOBS :
	  case IPP_OP_CANCEL_MY_JOBS :
              cancel_all_jobs(con, uri);
              break;

	  case IPP_OP_SET_JOB_ATTRIBUTES :
              set_job_attrs(con, uri);
              break;

	  case IPP_OP_SET_PRINTER_ATTRIBUTES :
              set_printer_attrs(con, uri);
              break;

	  case IPP_OP_HOLD_NEW_JOBS :
              hold_new_jobs(con, uri);
              break;

	  case IPP_OP_RELEASE_HELD_NEW_JOBS :
              release_held_new_jobs(con, uri);
              break;

	  case IPP_OP_CLOSE_JOB :
              close_job(con, uri);
              break;

	  case IPP_OP_CUPS_GET_DEFAULT :
              get_default(con);
              break;

	  case IPP_OP_CUPS_GET_PRINTERS :
              get_printers(con, 0);
              break;

	  case IPP_OP_CUPS_GET_CLASSES :
              get_printers(con, CUPS_PRINTER_CLASS);
              break;

	  case IPP_OP_CUPS_ADD_MODIFY_PRINTER :
              add_printer(con, uri);
              break;

	  case IPP_OP_CUPS_DELETE_PRINTER :
              delete_printer(con, uri);
              break;

	  case IPP_OP_CUPS_ADD_MODIFY_CLASS :
              add_class(con, uri);
              break;

	  case IPP_OP_CUPS_DELETE_CLASS :
              delete_printer(con, uri);
              break;

	  case IPP_OP_CUPS_ACCEPT_JOBS :
	  case IPP_OP_ENABLE_PRINTER :
              accept_jobs(con, uri);
              break;

	  case IPP_OP_CUPS_REJECT_JOBS :
	  case IPP_OP_DISABLE_PRINTER :
              reject_jobs(con, uri);
              break;

	  case IPP_OP_CUPS_SET_DEFAULT :
              set_default(con, uri);
              break;

	  case IPP_OP_CUPS_GET_DEVICES :
              get_devices(con);
              break;

          case IPP_OP_CUPS_GET_DOCUMENT :
	      get_document(con, uri);
	      break;

	  case IPP_OP_CUPS_GET_PPD :
              get_ppd(con, uri);
              break;

	  case IPP_OP_CUPS_GET_PPDS :
              get_ppds(con);
              break;

	  case IPP_OP_CUPS_MOVE_JOB :
              move_job(con, uri);
              break;

	  case IPP_OP_CUPS_AUTHENTICATE_JOB :
              authenticate_job(con, uri);
              break;

          case IPP_OP_CREATE_PRINTER_SUBSCRIPTIONS :
	  case IPP_OP_CREATE_JOB_SUBSCRIPTIONS :
	      create_subscriptions(con, uri);
	      break;

          case IPP_OP_GET_SUBSCRIPTION_ATTRIBUTES :
	      get_subscription_attrs(con, sub_id);
	      break;

	  case IPP_OP_GET_SUBSCRIPTIONS :
	      get_subscriptions(con, uri);
	      break;

	  case IPP_OP_RENEW_SUBSCRIPTION :
	      renew_subscription(con, sub_id);
	      break;

	  case IPP_OP_CANCEL_SUBSCRIPTION :
	      cancel_subscription(con, sub_id);
	      break;

          case IPP_OP_GET_NOTIFICATIONS :
	      get_notifications(con);
	      break;

	  default :
	      cupsdAddEvent(CUPSD_EVENT_SERVER_AUDIT, NULL, NULL,
                	    "%04X %s Operation %04X (%s) not supported",
			    IPP_OPERATION_NOT_SUPPORTED, con->http->hostname,
			    con->request->request.op.operation_id,
			    ippOpString(con->request->request.op.operation_id));

              send_ipp_status(con, IPP_OPERATION_NOT_SUPPORTED,
	                      _("%s not supported."),
			      ippOpString(
			          con->request->request.op.operation_id));
	      break;
	}
      }
    }
  }

  if (con->response)
  {
   /*
    * Sending data from the scheduler...
    */

    cupsdLogMessage(con->response->request.status.status_code
                        >= IPP_BAD_REQUEST &&
                    con->response->request.status.status_code
		        != IPP_NOT_FOUND ? CUPSD_LOG_ERROR : CUPSD_LOG_DEBUG,
                    "[Client %d] Returning IPP %s for %s (%s) from %s",
	            con->number,
	            ippErrorString(con->response->request.status.status_code),
		    ippOpString(con->request->request.op.operation_id),
		    uri ? uri->values[0].string.text : "no URI",
		    con->http->hostname);

    httpClearFields(con->http);

#ifdef CUPSD_USE_CHUNKING
   /*
    * Because older versions of CUPS (1.1.17 and older) and some IPP
    * clients do not implement chunking properly, we cannot use
    * chunking by default.  This may become the default in future
    * CUPS releases, or we might add a configuration directive for
    * it.
    */

    if (con->http->version == HTTP_1_1)
    {
      cupsdLogMessage(CUPSD_LOG_DEBUG,
		      "[Client %d] Transfer-Encoding: chunked",
		      con->number);

      cupsdSetLength(con->http, 0);
    }
    else
#endif /* CUPSD_USE_CHUNKING */
    {
      size_t	length;			/* Length of response */


      length = ippLength(con->response);

      if (con->file >= 0 && !con->pipe_pid)
      {
	struct stat	fileinfo;	/* File information */

	if (!fstat(con->file, &fileinfo))
	  length += (size_t)fileinfo.st_size;
      }

      cupsdLogMessage(CUPSD_LOG_DEBUG,
		      "[Client %d] Content-Length: " CUPS_LLFMT,
		      con->number, CUPS_LLCAST length);
      httpSetLength(con->http, length);
    }

    if (cupsdSendHeader(con, HTTP_OK, "application/ipp", CUPSD_AUTH_NONE))
    {
     /*
      * Tell the caller the response header was sent successfully...
      */

      cupsdAddSelect(httpGetFd(con->http), (cupsd_selfunc_t)cupsdReadClient,
		     (cupsd_selfunc_t)cupsdWriteClient, con);

      return (1);
    }
    else
    {
     /*
      * Tell the caller the response header could not be sent...
      */

      return (0);
    }
  }
  else
  {
   /*
    * Sending data from a subprocess like cups-deviced; tell the caller
    * everything is A-OK so far...
    */

    return (1);
  }
}
