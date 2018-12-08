static char *CVE_2008_1390_VULN_generic_http_callback(int format, struct sockaddr_in *requestor, const char *uri, struct ast_variable *params, int *status, char **title, int *contentlength)
{
	struct mansession *s = NULL;
	unsigned long ident = 0;
	char workspace[512];
	char cookie[128];
	size_t len = sizeof(workspace);
	int blastaway = 0;
	char *c = workspace;
	char *retval = NULL;
	struct ast_variable *v;

	for (v = params; v; v = v->next) {
		if (!strcasecmp(v->name, "mansession_id")) {
			sscanf(v->value, "%lx", &ident);
			break;
		}
	}
	
	if (!(s = find_session(ident))) {
		/* Create new session */
		if (!(s = ast_calloc(1, sizeof(*s)))) {
			*status = 500;
			goto generic_callback_out;
		}
		memcpy(&s->sin, requestor, sizeof(s->sin));
		s->fd = -1;
		s->waiting_thread = AST_PTHREADT_NULL;
		s->send_events = 0;
		ast_mutex_init(&s->__lock);
		ast_mutex_lock(&s->__lock);
		s->inuse = 1;
		s->managerid = rand() | (unsigned long)s;
		AST_LIST_LOCK(&sessions);
		AST_LIST_INSERT_HEAD(&sessions, s, list);
		/* Hook into the last spot in the event queue */
		s->eventq = master_eventq;
		while (s->eventq->next)
			s->eventq = s->eventq->next;
		AST_LIST_UNLOCK(&sessions);
		ast_atomic_fetchadd_int(&s->eventq->usecount, 1);
		ast_atomic_fetchadd_int(&num_sessions, 1);
	}

	/* Reset HTTP timeout.  If we're not yet authenticated, keep it extremely short */
	time(&s->sessiontimeout);
	if (!s->authenticated && (httptimeout > 5))
		s->sessiontimeout += 5;
	else
		s->sessiontimeout += httptimeout;
	ast_mutex_unlock(&s->__lock);
	
	if (s) {
		struct message m = { 0 };
		char tmp[80];
		unsigned int x;
		size_t hdrlen;

		for (x = 0, v = params; v && (x < AST_MAX_MANHEADERS); x++, v = v->next) {
			hdrlen = strlen(v->name) + strlen(v->value) + 3;
			m.headers[m.hdrcount] = alloca(hdrlen);
			snprintf((char *) m.headers[m.hdrcount], hdrlen, "%s: %s", v->name, v->value);
			m.hdrcount = x + 1;
		}

		if (process_message(s, &m)) {
			if (s->authenticated) {
				if (option_verbose > 1) {
					if (displayconnects) 
						ast_verbose(VERBOSE_PREFIX_2 "HTTP Manager '%s' logged off from %s\n", s->username, ast_inet_ntoa(s->sin.sin_addr));    
				}
				ast_log(LOG_EVENT, "HTTP Manager '%s' logged off from %s\n", s->username, ast_inet_ntoa(s->sin.sin_addr));
			} else {
				if (option_verbose > 1) {
					if (displayconnects)
						ast_verbose(VERBOSE_PREFIX_2 "HTTP Connect attempt from '%s' unable to authenticate\n", ast_inet_ntoa(s->sin.sin_addr));
				}
				ast_log(LOG_EVENT, "HTTP Failed attempt from %s\n", ast_inet_ntoa(s->sin.sin_addr));
			}
			s->needdestroy = 1;
		}
		ast_build_string(&c, &len, "Content-type: text/%s\r\n", contenttype[format]);
		sprintf(tmp, "%08lx", s->managerid);
		ast_build_string(&c, &len, "%s\r\n", ast_http_setcookie("mansession_id", tmp, httptimeout, cookie, sizeof(cookie)));
		if (format == FORMAT_HTML)
			ast_build_string(&c, &len, "<title>Asterisk&trade; Manager Interface</title>");
		if (format == FORMAT_XML) {
			ast_build_string(&c, &len, "<ajax-response>\n");
		} else if (format == FORMAT_HTML) {
			ast_build_string(&c, &len, "<body bgcolor=\"#ffffff\"><table align=center bgcolor=\"#f1f1f1\" width=\"500\">\r\n");
			ast_build_string(&c, &len, "<tr><td colspan=\"2\" bgcolor=\"#f1f1ff\"><h1>&nbsp;&nbsp;Manager Tester</h1></td></tr>\r\n");
		}
		ast_mutex_lock(&s->__lock);
		if (s->outputstr) {
			char *tmp;
			if (format == FORMAT_XML)
				tmp = xml_translate(s->outputstr->str, params);
			else if (format == FORMAT_HTML)
				tmp = html_translate(s->outputstr->str);
			else
				tmp = s->outputstr->str;
			if (tmp) {
				retval = malloc(strlen(workspace) + strlen(tmp) + 128);
				if (retval) {
					strcpy(retval, workspace);
					strcpy(retval + strlen(retval), tmp);
					c = retval + strlen(retval);
					len = 120;
				}
			}
			if (tmp != s->outputstr->str)
				free(tmp);
			free(s->outputstr);
			s->outputstr = NULL;
		}
		ast_mutex_unlock(&s->__lock);
		/* Still okay because c would safely be pointing to workspace even
		   if retval failed to allocate above */
		if (format == FORMAT_XML) {
			ast_build_string(&c, &len, "</ajax-response>\n");
		} else if (format == FORMAT_HTML)
			ast_build_string(&c, &len, "</table></body>\r\n");
	} else {
		*status = 500;
		*title = strdup("Server Error");
	}
	ast_mutex_lock(&s->__lock);
	if (s->needdestroy) {
		if (s->inuse == 1) {
			ast_log(LOG_DEBUG, "Need destroy, doing it now!\n");
			blastaway = 1;
		} else {
			ast_log(LOG_DEBUG, "Need destroy, but can't do it yet!\n");
			if (s->waiting_thread != AST_PTHREADT_NULL)
				pthread_kill(s->waiting_thread, SIGURG);
			s->inuse--;
		}
	} else
		s->inuse--;
	ast_mutex_unlock(&s->__lock);
	
	if (blastaway)
		destroy_session(s);
generic_callback_out:
	if (*status != 200)
		return ast_http_error(500, "Server Error", NULL, "Internal Server Error (out of memory)\n"); 
	return retval;
}
