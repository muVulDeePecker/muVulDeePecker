static void *CVE_2015_3008_VULN_handle_tcptls_connection(void *data)
{
	struct ast_tcptls_session_instance *tcptls_session = data;
#ifdef DO_SSL
	int (*ssl_setup)(SSL *) = (tcptls_session->client) ? SSL_connect : SSL_accept;
	int ret;
	char err[256];
#endif

	/* TCP/TLS connections are associated with external protocols, and
	 * should not be allowed to execute 'dangerous' functions. This may
	 * need to be pushed down into the individual protocol handlers, but
	 * this seems like a good general policy.
	 */
	if (ast_thread_inhibit_escalations()) {
		ast_log(LOG_ERROR, "Failed to inhibit privilege escalations; killing connection\n");
		ast_tcptls_close_session_file(tcptls_session);
		ao2_ref(tcptls_session, -1);
		return NULL;
	}

	tcptls_session->stream_cookie = tcptls_stream_alloc();
	if (!tcptls_session->stream_cookie) {
		ast_tcptls_close_session_file(tcptls_session);
		ao2_ref(tcptls_session, -1);
		return NULL;
	}

	/*
	* open a FILE * as appropriate.
	*/
	if (!tcptls_session->parent->tls_cfg) {
		tcptls_session->f = tcptls_stream_fopen(tcptls_session->stream_cookie, NULL,
			tcptls_session->fd, -1);
		if (tcptls_session->f) {
			if (setvbuf(tcptls_session->f, NULL, _IONBF, 0)) {
				ast_tcptls_close_session_file(tcptls_session);
			}
		}
	}
#ifdef DO_SSL
	else if ( (tcptls_session->ssl = SSL_new(tcptls_session->parent->tls_cfg->ssl_ctx)) ) {
		SSL_set_fd(tcptls_session->ssl, tcptls_session->fd);
		if ((ret = ssl_setup(tcptls_session->ssl)) <= 0) {
			ast_verb(2, "Problem setting up ssl connection: %s\n", ERR_error_string(ERR_get_error(), err));
		} else if ((tcptls_session->f = tcptls_stream_fopen(tcptls_session->stream_cookie,
			tcptls_session->ssl, tcptls_session->fd, -1))) {
			if ((tcptls_session->client && !ast_test_flag(&tcptls_session->parent->tls_cfg->flags, AST_SSL_DONT_VERIFY_SERVER))
				|| (!tcptls_session->client && ast_test_flag(&tcptls_session->parent->tls_cfg->flags, AST_SSL_VERIFY_CLIENT))) {
				X509 *peer;
				long res;
				peer = SSL_get_peer_certificate(tcptls_session->ssl);
				if (!peer) {
					ast_log(LOG_ERROR, "No peer SSL certificate to verify\n");
					ast_tcptls_close_session_file(tcptls_session);
					ao2_ref(tcptls_session, -1);
					return NULL;
				}

				res = SSL_get_verify_result(tcptls_session->ssl);
				if (res != X509_V_OK) {
					ast_log(LOG_ERROR, "Certificate did not verify: %s\n", X509_verify_cert_error_string(res));
					X509_free(peer);
					ast_tcptls_close_session_file(tcptls_session);
					ao2_ref(tcptls_session, -1);
					return NULL;
				}
				if (!ast_test_flag(&tcptls_session->parent->tls_cfg->flags, AST_SSL_IGNORE_COMMON_NAME)) {
					ASN1_STRING *str;
					unsigned char *str2;
					X509_NAME *name = X509_get_subject_name(peer);
					int pos = -1;
					int found = 0;

					for (;;) {
						/* Walk the certificate to check all available "Common Name" */
						/* XXX Probably should do a gethostbyname on the hostname and compare that as well */
						pos = X509_NAME_get_index_by_NID(name, NID_commonName, pos);
						if (pos < 0)
							break;
						str = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, pos));
						ASN1_STRING_to_UTF8(&str2, str);
						if (str2) {
							if (!strcasecmp(tcptls_session->parent->hostname, (char *) str2))
								found = 1;
							ast_debug(3, "SSL Common Name compare s1='%s' s2='%s'\n", tcptls_session->parent->hostname, str2);
							OPENSSL_free(str2);
						}
						if (found)
							break;
					}
					if (!found) {
						ast_log(LOG_ERROR, "Certificate common name did not match (%s)\n", tcptls_session->parent->hostname);
						X509_free(peer);
						ast_tcptls_close_session_file(tcptls_session);
						ao2_ref(tcptls_session, -1);
						return NULL;
					}
				}
				X509_free(peer);
			}
		}
		if (!tcptls_session->f)	/* no success opening descriptor stacking */
			SSL_free(tcptls_session->ssl);
   }
#endif /* DO_SSL */

	if (!tcptls_session->f) {
		ast_tcptls_close_session_file(tcptls_session);
		ast_log(LOG_WARNING, "FILE * open failed!\n");
#ifndef DO_SSL
		if (tcptls_session->parent->tls_cfg) {
			ast_log(LOG_WARNING, "Attempted a TLS connection without OpenSSL support.  This will not work!\n");
		}
#endif
		ao2_ref(tcptls_session, -1);
		return NULL;
	}

	if (tcptls_session->parent->worker_fn) {
		return tcptls_session->parent->worker_fn(tcptls_session);
	} else {
		return tcptls_session;
	}
}
