static void *CVE_2011_1175_VULN_handle_tcptls_connection(void *data)
{
	struct ast_tcptls_session_instance *tcptls_session = data;
#ifdef DO_SSL
	int (*ssl_setup)(SSL *) = (tcptls_session->client) ? SSL_connect : SSL_accept;
	int ret;
	char err[256];
#endif

	/*
	* open a FILE * as appropriate.
	*/
	if (!tcptls_session->parent->tls_cfg) {
		tcptls_session->f = fdopen(tcptls_session->fd, "w+");
		setvbuf(tcptls_session->f, NULL, _IONBF, 0);
	}
#ifdef DO_SSL
	else if ( (tcptls_session->ssl = SSL_new(tcptls_session->parent->tls_cfg->ssl_ctx)) ) {
		SSL_set_fd(tcptls_session->ssl, tcptls_session->fd);
		if ((ret = ssl_setup(tcptls_session->ssl)) <= 0) {
			ast_verb(2, "Problem setting up ssl connection: %s\n", ERR_error_string(ERR_get_error(), err));
		} else {
#if defined(HAVE_FUNOPEN)	/* the BSD interface */
			tcptls_session->f = funopen(tcptls_session->ssl, ssl_read, ssl_write, NULL, ssl_close);

#elif defined(HAVE_FOPENCOOKIE)	/* the glibc/linux interface */
			static const cookie_io_functions_t cookie_funcs = {
				ssl_read, ssl_write, NULL, ssl_close
			};
			tcptls_session->f = fopencookie(tcptls_session->ssl, "w+", cookie_funcs);
#else
			/* could add other methods here */
			ast_debug(2, "no tcptls_session->f methods attempted!");
#endif
			if ((tcptls_session->client && !ast_test_flag(&tcptls_session->parent->tls_cfg->flags, AST_SSL_DONT_VERIFY_SERVER))
				|| (!tcptls_session->client && ast_test_flag(&tcptls_session->parent->tls_cfg->flags, AST_SSL_VERIFY_CLIENT))) {
				X509 *peer;
				long res;
				peer = SSL_get_peer_certificate(tcptls_session->ssl);
				if (!peer)
					ast_log(LOG_WARNING, "No peer SSL certificate\n");
				res = SSL_get_verify_result(tcptls_session->ssl);
				if (res != X509_V_OK)
					ast_log(LOG_ERROR, "Certificate did not verify: %s\n", X509_verify_cert_error_string(res));
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
						if (peer)
							X509_free(peer);
						close(tcptls_session->fd);
						fclose(tcptls_session->f);
						ao2_ref(tcptls_session, -1);
						return NULL;
					}
				}
				if (peer)
					X509_free(peer);
			}
		}
		if (!tcptls_session->f)	/* no success opening descriptor stacking */
			SSL_free(tcptls_session->ssl);
   }
#endif /* DO_SSL */

	if (!tcptls_session->f) {
		close(tcptls_session->fd);
		ast_log(LOG_WARNING, "FILE * open failed!\n");
#ifndef DO_SSL
		if (tcptls_session->parent->tls_cfg) {
			ast_log(LOG_WARNING, "Attempted a TLS connection without OpenSSL support.  This will not work!\n");
		}
#endif
		ao2_ref(tcptls_session, -1);
		return NULL;
	}

	if (tcptls_session && tcptls_session->parent->worker_fn)
		return tcptls_session->parent->worker_fn(tcptls_session);
	else
		return tcptls_session;
}
