static int CVE_2013_5642_VULN_process_sdp(struct sip_pvt *p, struct sip_request *req, int t38action)
{
	int res = 0;

	/* Iterators for SDP parsing */
	int start = req->sdp_start;
	int next = start;
	int iterator = start;

	/* Temporary vars for SDP parsing */
	char type = '\0';
	const char *value = NULL;
	const char *m = NULL;           /* SDP media offer */
	const char *nextm = NULL;
	int len = -1;

	/* Host information */
	struct ast_sockaddr sessionsa;
	struct ast_sockaddr audiosa;
	struct ast_sockaddr videosa;
	struct ast_sockaddr textsa;
	struct ast_sockaddr imagesa;
	struct ast_sockaddr *sa = NULL;		/*!< RTP audio destination IP address */
	struct ast_sockaddr *vsa = NULL;	/*!< RTP video destination IP address */
	struct ast_sockaddr *tsa = NULL;	/*!< RTP text destination IP address */
	struct ast_sockaddr *isa = NULL;	/*!< UDPTL image destination IP address */
 	int portno = -1;			/*!< RTP audio destination port number */
 	int vportno = -1;			/*!< RTP video destination port number */
	int tportno = -1;			/*!< RTP text destination port number */
	int udptlportno = -1;			/*!< UDPTL image destination port number */

	/* Peer capability is the capability in the SDP, non codec is RFC2833 DTMF (101) */
	struct ast_format_cap *peercapability = ast_format_cap_alloc_nolock();
	struct ast_format_cap *vpeercapability = ast_format_cap_alloc_nolock();
	struct ast_format_cap *tpeercapability = ast_format_cap_alloc_nolock();

	int peernoncodeccapability = 0, vpeernoncodeccapability = 0, tpeernoncodeccapability = 0;

	struct ast_rtp_codecs newaudiortp, newvideortp, newtextrtp;
	struct ast_format_cap *newjointcapability = ast_format_cap_alloc_nolock(); /* Negotiated capability */
	struct ast_format_cap *newpeercapability = ast_format_cap_alloc_nolock();
	int newnoncodeccapability;

	const char *codecs;
	int codec;

	/* SRTP */
	int secure_audio = FALSE;
	int secure_video = FALSE;

	/* Others */
	int sendonly = -1;
	int numberofports;
	int numberofmediastreams = 0;
	int last_rtpmap_codec = 0;
	int red_data_pt[10];		/* For T.140 RED */
	int red_num_gen = 0;		/* For T.140 RED */
	char red_fmtp[100] = "empty";	/* For T.140 RED */
	int debug = sip_debug_test_pvt(p);

	/* START UNKNOWN */
	char buf[SIPBUFSIZE];
	struct ast_format tmp_fmt;
	/* END UNKNOWN */

	/* Initial check */
	if (!p->rtp) {
		ast_log(LOG_ERROR, "Got SDP but have no RTP session allocated.\n");
		res = -1;
		goto process_sdp_cleanup;
	}
	if (!peercapability || !vpeercapability || !tpeercapability || !newpeercapability || !newjointcapability) {
		res = -1;
		goto process_sdp_cleanup;
	}

	/* Make sure that the codec structures are all cleared out */
	ast_rtp_codecs_payloads_clear(&newaudiortp, NULL);
	ast_rtp_codecs_payloads_clear(&newvideortp, NULL);
	ast_rtp_codecs_payloads_clear(&newtextrtp, NULL);

	/* Update our last rtprx when we receive an SDP, too */
	p->lastrtprx = p->lastrtptx = time(NULL); /* XXX why both ? */

	memset(p->offered_media, 0, sizeof(p->offered_media));

	/* Scan for the first media stream (m=) line to limit scanning of globals */
	nextm = get_sdp_iterate(&next, req, "m");
	if (ast_strlen_zero(nextm)) {
		ast_log(LOG_WARNING, "Insufficient information for SDP (m= not found)\n");
		res = -1;
		goto process_sdp_cleanup;
 	}

	/* Scan session level SDP parameters (lines before first media stream) */
	while ((type = get_sdp_line(&iterator, next - 1, req, &value)) != '\0') {
		int processed = FALSE;
		switch (type) {
		case 'o':
			/* If we end up receiving SDP that doesn't actually modify the session we don't want to treat this as a fatal
			 * error. We just want to ignore the SDP and let the rest of the packet be handled as normal.
			 */
			if (!process_sdp_o(value, p)) {
				res = (p->session_modify == FALSE) ? 0 : -1;
				goto process_sdp_cleanup;
			}
			processed = TRUE;
			break;
		case 'c':
			if (process_sdp_c(value, &sessionsa)) {
				processed = TRUE;
				sa = &sessionsa;
				vsa = sa;
				tsa = sa;
				isa = sa;
			}
			break;
		case 'a':
			if (process_sdp_a_sendonly(value, &sendonly)) {
				processed = TRUE;
			}
			else if (process_sdp_a_audio(value, p, &newaudiortp, &last_rtpmap_codec))
				processed = TRUE;
			else if (process_sdp_a_video(value, p, &newvideortp, &last_rtpmap_codec))
				processed = TRUE;
			else if (process_sdp_a_text(value, p, &newtextrtp, red_fmtp, &red_num_gen, red_data_pt, &last_rtpmap_codec))
				processed = TRUE;
			else if (process_sdp_a_image(value, p))
				processed = TRUE;
			break;
		}

		ast_debug(3, "Processing session-level SDP %c=%s... %s\n", type, value, (processed == TRUE)? "OK." : "UNSUPPORTED OR FAILED.");
	}

	/* default: novideo and notext set */
	p->novideo = TRUE;
	p->notext = TRUE;

	/* Scan media stream (m=) specific parameters loop */
	while (!ast_strlen_zero(nextm)) {
		int audio = FALSE;
		int video = FALSE;
		int image = FALSE;
		int text = FALSE;
		int processed_crypto = FALSE;
		char protocol[5] = {0,};
		int x;

		numberofports = 0;
		len = -1;
		start = next;
		m = nextm;
		iterator = next;
		nextm = get_sdp_iterate(&next, req, "m");

		/* Check for 'audio' media offer */
		if (strncmp(m, "audio ", 6) == 0) {
			if ((sscanf(m, "audio %30u/%30u RTP/%4s %n", &x, &numberofports, protocol, &len) == 3 && len > 0) ||
			    (sscanf(m, "audio %30u RTP/%4s %n", &x, protocol, &len) == 2 && len > 0)) {
				if (x == 0) {
					ast_log(LOG_WARNING, "Ignoring audio media offer because port number is zero\n");
					continue;
				}

				/* Check number of ports offered for stream */
				if (numberofports > 1) {
					ast_log(LOG_WARNING, "%d ports offered for audio media, not supported by Asterisk. Will try anyway...\n", numberofports);
				}

				if (!strcmp(protocol, "SAVP")) {
					secure_audio = 1;
				} else if (strcmp(protocol, "AVP")) {
					ast_log(LOG_WARNING, "Unknown RTP profile in audio offer: %s\n", m);
					continue;
				}

				if (p->offered_media[SDP_AUDIO].order_offered) {
					ast_log(LOG_WARNING, "Rejecting non-primary audio stream: %s\n", m);
					res = -1;
					goto process_sdp_cleanup;
				}

				audio = TRUE;
				p->offered_media[SDP_AUDIO].order_offered = ++numberofmediastreams;
				portno = x;

				/* Scan through the RTP payload types specified in a "m=" line: */
				codecs = m + len;
				ast_copy_string(p->offered_media[SDP_AUDIO].codecs, codecs, sizeof(p->offered_media[SDP_AUDIO].codecs));
				for (; !ast_strlen_zero(codecs); codecs = ast_skip_blanks(codecs + len)) {
					if (sscanf(codecs, "%30u%n", &codec, &len) != 1) {
						ast_log(LOG_WARNING, "Invalid syntax in RTP audio format list: %s\n", codecs);
						res = -1;
						goto process_sdp_cleanup;
					}
					if (debug) {
						ast_verbose("Found RTP audio format %d\n", codec);
					}

					ast_rtp_codecs_payloads_set_m_type(&newaudiortp, NULL, codec);
				}
			} else {
				ast_log(LOG_WARNING, "Rejecting audio media offer due to invalid or unsupported syntax: %s\n", m);
				res = -1;
				goto process_sdp_cleanup;
			}
		}
		/* Check for 'video' media offer */
		else if (strncmp(m, "video ", 6) == 0) {
			if ((sscanf(m, "video %30u/%30u RTP/%4s %n", &x, &numberofports, protocol, &len) == 3 && len > 0) ||
			    (sscanf(m, "video %30u RTP/%4s %n", &x, protocol, &len) == 2 && len > 0)) {
				if (x == 0) {
					ast_log(LOG_WARNING, "Ignoring video media offer because port number is zero\n");
					continue;
				}

				/* Check number of ports offered for stream */
				if (numberofports > 1) {
					ast_log(LOG_WARNING, "%d ports offered for video media, not supported by Asterisk. Will try anyway...\n", numberofports);
				}

				if (!strcmp(protocol, "SAVP")) {
					secure_video = 1;
				} else if (strcmp(protocol, "AVP")) {
					ast_log(LOG_WARNING, "Unknown RTP profile in video offer: %s\n", m);
					continue;
				}

				if (p->offered_media[SDP_VIDEO].order_offered) {
					ast_log(LOG_WARNING, "Rejecting non-primary video stream: %s\n", m);
					res = -1;
					goto process_sdp_cleanup;
				}

				video = TRUE;
				p->novideo = FALSE;
				p->offered_media[SDP_VIDEO].order_offered = ++numberofmediastreams;
				vportno = x;

				/* Scan through the RTP payload types specified in a "m=" line: */
				codecs = m + len;
				ast_copy_string(p->offered_media[SDP_VIDEO].codecs, codecs, sizeof(p->offered_media[SDP_VIDEO].codecs));
				for (; !ast_strlen_zero(codecs); codecs = ast_skip_blanks(codecs + len)) {
					if (sscanf(codecs, "%30u%n", &codec, &len) != 1) {
						ast_log(LOG_WARNING, "Invalid syntax in RTP video format list: %s\n", codecs);
						res = -1;
						goto process_sdp_cleanup;
					}
					if (debug) {
						ast_verbose("Found RTP video format %d\n", codec);
					}
					ast_rtp_codecs_payloads_set_m_type(&newvideortp, NULL, codec);
				}
			} else {
				ast_log(LOG_WARNING, "Rejecting video media offer due to invalid or unsupported syntax: %s\n", m);
				res = -1;
				goto process_sdp_cleanup;
			}
		}
		/* Check for 'text' media offer */
		else if (strncmp(m, "text ", 5) == 0) {
			if ((sscanf(m, "text %30u/%30u RTP/AVP %n", &x, &numberofports, &len) == 2 && len > 0) ||
			    (sscanf(m, "text %30u RTP/AVP %n", &x, &len) == 1 && len > 0)) {
				if (x == 0) {
					ast_log(LOG_WARNING, "Ignoring text media offer because port number is zero\n");
					continue;
				}

				/* Check number of ports offered for stream */
				if (numberofports > 1) {
					ast_log(LOG_WARNING, "%d ports offered for text media, not supported by Asterisk. Will try anyway...\n", numberofports);
				}

				if (p->offered_media[SDP_TEXT].order_offered) {
					ast_log(LOG_WARNING, "Rejecting non-primary text stream: %s\n", m);
					res = -1;
					goto process_sdp_cleanup;
				}

				text = TRUE;
				p->notext = FALSE;
				p->offered_media[SDP_TEXT].order_offered = ++numberofmediastreams;
				tportno = x;

				/* Scan through the RTP payload types specified in a "m=" line: */
				codecs = m + len;
				ast_copy_string(p->offered_media[SDP_TEXT].codecs, codecs, sizeof(p->offered_media[SDP_TEXT].codecs));
				for (; !ast_strlen_zero(codecs); codecs = ast_skip_blanks(codecs + len)) {
					if (sscanf(codecs, "%30u%n", &codec, &len) != 1) {
						ast_log(LOG_WARNING, "Invalid syntax in RTP video format list: %s\n", codecs);
						res = -1;
						goto process_sdp_cleanup;
					}
					if (debug) {
						ast_verbose("Found RTP text format %d\n", codec);
					}
					ast_rtp_codecs_payloads_set_m_type(&newtextrtp, NULL, codec);
				}
			} else {
				ast_log(LOG_WARNING, "Rejecting text media offer due to invalid or unsupported syntax: %s\n", m);
				res = -1;
				goto process_sdp_cleanup;
			}
		}
		/* Check for 'image' media offer */
		else if (strncmp(m, "image ", 6) == 0) {
			if (((sscanf(m, "image %30u udptl t38%n", &x, &len) == 1 && len > 0) ||
			     (sscanf(m, "image %30u UDPTL t38%n", &x, &len) == 1 && len > 0))) {
				if (x == 0) {
					ast_log(LOG_WARNING, "Ignoring image media offer because port number is zero\n");
					continue;
				}

				if (initialize_udptl(p)) {
					ast_log(LOG_WARNING, "Rejecting offer with image stream due to UDPTL initialization failure\n");
					res = -1;
					goto process_sdp_cleanup;
				}

				if (p->offered_media[SDP_IMAGE].order_offered) {
					ast_log(LOG_WARNING, "Rejecting non-primary image stream: %s\n", m);
					res = -1;
					goto process_sdp_cleanup;
				}

				image = TRUE;
				if (debug) {
					ast_verbose("Got T.38 offer in SDP in dialog %s\n", p->callid);
				}

				p->offered_media[SDP_IMAGE].order_offered = ++numberofmediastreams;
				udptlportno = x;

				if (p->t38.state != T38_ENABLED) {
					memset(&p->t38.their_parms, 0, sizeof(p->t38.their_parms));

					/* default EC to none, the remote end should
					 * respond with the EC they want to use */
					ast_udptl_set_error_correction_scheme(p->udptl, UDPTL_ERROR_CORRECTION_NONE);
				}
			} else {
				ast_log(LOG_WARNING, "Rejecting image media offer due to invalid or unsupported syntax: %s\n", m);
				res = -1;
				goto process_sdp_cleanup;
			}
		} else {
			ast_log(LOG_WARNING, "Unsupported top-level media type in offer: %s\n", m);
			continue;
		}

		/* Media stream specific parameters */
		while ((type = get_sdp_line(&iterator, next - 1, req, &value)) != '\0') {
			int processed = FALSE;

			switch (type) {
			case 'c':
				if (audio) {
					if (process_sdp_c(value, &audiosa)) {
						processed = TRUE;
						sa = &audiosa;
					}
				} else if (video) {
					if (process_sdp_c(value, &videosa)) {
						processed = TRUE;
						vsa = &videosa;
					}
				} else if (text) {
					if (process_sdp_c(value, &textsa)) {
						processed = TRUE;
						tsa = &textsa;
					}
				} else if (image) {
					if (process_sdp_c(value, &imagesa)) {
						processed = TRUE;
						isa = &imagesa;
					}
				}
				break;
			case 'a':
				/* Audio specific scanning */
				if (audio) {
					if (process_sdp_a_sendonly(value, &sendonly)) {
						processed = TRUE;
					} else if (!processed_crypto && process_crypto(p, p->rtp, &p->srtp, value)) {
						processed_crypto = TRUE;
						processed = TRUE;
					} else if (process_sdp_a_audio(value, p, &newaudiortp, &last_rtpmap_codec)) {
						processed = TRUE;
					}
				}
				/* Video specific scanning */
				else if (video) {
					if (!processed_crypto && process_crypto(p, p->vrtp, &p->vsrtp, value)) {
						processed_crypto = TRUE;
						processed = TRUE;
					} else if (process_sdp_a_video(value, p, &newvideortp, &last_rtpmap_codec)) {
						processed = TRUE;
					}
				}
				/* Text (T.140) specific scanning */
				else if (text) {
					if (process_sdp_a_text(value, p, &newtextrtp, red_fmtp, &red_num_gen, red_data_pt, &last_rtpmap_codec)) {
						processed = TRUE;
					} else if (!processed_crypto && process_crypto(p, p->trtp, &p->tsrtp, value)) {
						processed_crypto = TRUE;
						processed = TRUE;
					}
				}
				/* Image (T.38 FAX) specific scanning */
				else if (image) {
					if (process_sdp_a_image(value, p))
						processed = TRUE;
				}
				break;
			}

			ast_debug(3, "Processing media-level (%s) SDP %c=%s... %s\n",
				  (audio == TRUE)? "audio" : (video == TRUE)? "video" : (text == TRUE)? "text" : "image",
				  type, value,
				  (processed == TRUE)? "OK." : "UNSUPPORTED OR FAILED.");
		}

		/* Ensure crypto lines are provided where necessary */
		if (audio && secure_audio && !processed_crypto) {
			ast_log(LOG_WARNING, "Rejecting secure audio stream without encryption details: %s\n", m);
			return -1;
		} else if (video && secure_video && !processed_crypto) {
			ast_log(LOG_WARNING, "Rejecting secure video stream without encryption details: %s\n", m);
			return -1;
		}
	}

	/* Sanity checks */
	if (!sa && !vsa && !tsa && !isa) {
		ast_log(LOG_WARNING, "Insufficient information in SDP (c=)...\n");
		res = -1;
		goto process_sdp_cleanup;
	}

	if ((portno == -1) &&
	    (vportno == -1) &&
	    (tportno == -1) &&
	    (udptlportno == -1)) {
		ast_log(LOG_WARNING, "Failing due to no acceptable offer found\n");
		res = -1;
		goto process_sdp_cleanup;
	}

	if (secure_audio && !(p->srtp && (ast_test_flag(p->srtp, SRTP_CRYPTO_OFFER_OK)))) {
		ast_log(LOG_WARNING, "Can't provide secure audio requested in SDP offer\n");
		res = -1;
		goto process_sdp_cleanup;
	}

	if (!secure_audio && p->srtp) {
		ast_log(LOG_WARNING, "We are requesting SRTP for audio, but they responded without it!\n");
		res = -1;
		goto process_sdp_cleanup;
	}

	if (secure_video && !(p->vsrtp && (ast_test_flag(p->vsrtp, SRTP_CRYPTO_OFFER_OK)))) {
		ast_log(LOG_WARNING, "Can't provide secure video requested in SDP offer\n");
		res = -1;
		goto process_sdp_cleanup;
	}

	if (!p->novideo && !secure_video && p->vsrtp) {
		ast_log(LOG_WARNING, "We are requesting SRTP for video, but they responded without it!\n");
		res = -1;
		goto process_sdp_cleanup;
	}

	if (!(secure_audio || secure_video) && ast_test_flag(&p->flags[1], SIP_PAGE2_USE_SRTP)) {
		ast_log(LOG_WARNING, "Matched device setup to use SRTP, but request was not!\n");
		res = -1;
		goto process_sdp_cleanup;
	}

	if (udptlportno == -1) {
		change_t38_state(p, T38_DISABLED);
	}

	/* Now gather all of the codecs that we are asked for: */
	ast_rtp_codecs_payload_formats(&newaudiortp, peercapability, &peernoncodeccapability);
	ast_rtp_codecs_payload_formats(&newvideortp, vpeercapability, &vpeernoncodeccapability);
	ast_rtp_codecs_payload_formats(&newtextrtp, tpeercapability, &tpeernoncodeccapability);

	ast_format_cap_append(newpeercapability, peercapability);
	ast_format_cap_append(newpeercapability, vpeercapability);
	ast_format_cap_append(newpeercapability, tpeercapability);

	ast_format_cap_joint_copy(p->caps, newpeercapability, newjointcapability);
	if (ast_format_cap_is_empty(newjointcapability) && udptlportno == -1) {
		ast_log(LOG_NOTICE, "No compatible codecs, not accepting this offer!\n");
		/* Do NOT Change current setting */
		res = -1;
		goto process_sdp_cleanup;
	}

	newnoncodeccapability = p->noncodeccapability & peernoncodeccapability;

	if (debug) {
		/* shame on whoever coded this.... */
		char s1[SIPBUFSIZE], s2[SIPBUFSIZE], s3[SIPBUFSIZE], s4[SIPBUFSIZE], s5[SIPBUFSIZE];

		ast_verbose("Capabilities: us - %s, peer - audio=%s/video=%s/text=%s, combined - %s\n",
			    ast_getformatname_multiple(s1, SIPBUFSIZE, p->caps),
			    ast_getformatname_multiple(s2, SIPBUFSIZE, peercapability),
			    ast_getformatname_multiple(s3, SIPBUFSIZE, vpeercapability),
			    ast_getformatname_multiple(s4, SIPBUFSIZE, tpeercapability),
			    ast_getformatname_multiple(s5, SIPBUFSIZE, newjointcapability));
	}
	if (debug) {
		struct ast_str *s1 = ast_str_alloca(SIPBUFSIZE);
		struct ast_str *s2 = ast_str_alloca(SIPBUFSIZE);
		struct ast_str *s3 = ast_str_alloca(SIPBUFSIZE);

		ast_verbose("Non-codec capabilities (dtmf): us - %s, peer - %s, combined - %s\n",
			    ast_rtp_lookup_mime_multiple2(s1, NULL, p->noncodeccapability, 0, 0),
			    ast_rtp_lookup_mime_multiple2(s2, NULL, peernoncodeccapability, 0, 0),
			    ast_rtp_lookup_mime_multiple2(s3, NULL, newnoncodeccapability, 0, 0));
	}

	if (portno != -1 || vportno != -1 || tportno != -1) {
		/* We are now ready to change the sip session and RTP structures with the offered codecs, since
		   they are acceptable */
		ast_format_cap_copy(p->jointcaps, newjointcapability);                /* Our joint codec profile for this call */
		ast_format_cap_copy(p->peercaps, newpeercapability);                  /* The other side's capability in latest offer */
		p->jointnoncodeccapability = newnoncodeccapability;     /* DTMF capabilities */

		/* respond with single most preferred joint codec, limiting the other side's choice */
		if (ast_test_flag(&p->flags[1], SIP_PAGE2_PREFERRED_CODEC)) {
			ast_codec_choose(&p->prefs, p->jointcaps, 1, &tmp_fmt);
			ast_format_cap_set(p->jointcaps, &tmp_fmt);
		}
	}

	/* Setup audio address and port */
	if (p->rtp) {
		if (portno > 0) {
			ast_sockaddr_set_port(sa, portno);
			ast_rtp_instance_set_remote_address(p->rtp, sa);
			if (debug) {
				ast_verbose("Peer audio RTP is at port %s\n",
					    ast_sockaddr_stringify(sa));
			}

			ast_rtp_codecs_payloads_copy(&newaudiortp, ast_rtp_instance_get_codecs(p->rtp), p->rtp);
			/* Ensure RTCP is enabled since it may be inactive
			   if we're coming back from a T.38 session */
			ast_rtp_instance_set_prop(p->rtp, AST_RTP_PROPERTY_RTCP, 1);
			/* Ensure audio RTCP reads are enabled */
			if (p->owner) {
				ast_channel_set_fd(p->owner, 1, ast_rtp_instance_fd(p->rtp, 1));
			}

			if (ast_test_flag(&p->flags[0], SIP_DTMF) == SIP_DTMF_AUTO) {
				ast_clear_flag(&p->flags[0], SIP_DTMF);
				if (newnoncodeccapability & AST_RTP_DTMF) {
					/* XXX Would it be reasonable to drop the DSP at this point? XXX */
					ast_set_flag(&p->flags[0], SIP_DTMF_RFC2833);
					/* Since RFC2833 is now negotiated we need to change some properties of the RTP stream */
					ast_rtp_instance_set_prop(p->rtp, AST_RTP_PROPERTY_DTMF, 1);
					ast_rtp_instance_set_prop(p->rtp, AST_RTP_PROPERTY_DTMF_COMPENSATE, ast_test_flag(&p->flags[1], SIP_PAGE2_RFC2833_COMPENSATE));
				} else {
					ast_set_flag(&p->flags[0], SIP_DTMF_INBAND);
				}
			}
		} else if (udptlportno > 0) {
			if (debug)
				ast_verbose("Got T.38 Re-invite without audio. Keeping RTP active during T.38 session.\n");
			/* Prevent audio RTCP reads */
			if (p->owner) {
				ast_channel_set_fd(p->owner, 1, -1);
			}
			/* Silence RTCP while audio RTP is inactive */
			ast_rtp_instance_set_prop(p->rtp, AST_RTP_PROPERTY_RTCP, 0);
		} else {
			ast_rtp_instance_stop(p->rtp);
			if (debug)
				ast_verbose("Peer doesn't provide audio\n");
		}
	}

	/* Setup video address and port */
	if (p->vrtp) {
		if (vportno > 0) {
			ast_sockaddr_set_port(vsa, vportno);
			ast_rtp_instance_set_remote_address(p->vrtp, vsa);
			if (debug) {
				ast_verbose("Peer video RTP is at port %s\n",
					    ast_sockaddr_stringify(vsa));
			}
			ast_rtp_codecs_payloads_copy(&newvideortp, ast_rtp_instance_get_codecs(p->vrtp), p->vrtp);
		} else {
			ast_rtp_instance_stop(p->vrtp);
			if (debug)
				ast_verbose("Peer doesn't provide video\n");
		}
	}

	/* Setup text address and port */
	if (p->trtp) {
		if (tportno > 0) {
			ast_sockaddr_set_port(tsa, tportno);
			ast_rtp_instance_set_remote_address(p->trtp, tsa);
			if (debug) {
				ast_verbose("Peer T.140 RTP is at port %s\n",
					    ast_sockaddr_stringify(tsa));
			}
			if (ast_format_cap_iscompatible(p->jointcaps, ast_format_set(&tmp_fmt, AST_FORMAT_T140RED, 0))) {
				p->red = 1;
				ast_rtp_red_init(p->trtp, 300, red_data_pt, 2);
			} else {
				p->red = 0;
			}
			ast_rtp_codecs_payloads_copy(&newtextrtp, ast_rtp_instance_get_codecs(p->trtp), p->trtp);
		} else {
			ast_rtp_instance_stop(p->trtp);
			if (debug)
				ast_verbose("Peer doesn't provide T.140\n");
		}
	}

	/* Setup image address and port */
	if (p->udptl) {
		if (udptlportno > 0) {
			if (ast_test_flag(&p->flags[1], SIP_PAGE2_SYMMETRICRTP) && ast_test_flag(&p->flags[1], SIP_PAGE2_UDPTL_DESTINATION)) {
				ast_rtp_instance_get_remote_address(p->rtp, isa);
				if (!ast_sockaddr_isnull(isa) && debug) {
					ast_debug(1, "Peer T.38 UDPTL is set behind NAT and with destination, destination address now %s\n", ast_sockaddr_stringify(isa));
				}
			}
			ast_sockaddr_set_port(isa, udptlportno);
			ast_udptl_set_peer(p->udptl, isa);
			if (debug)
				ast_debug(1,"Peer T.38 UDPTL is at port %s\n", ast_sockaddr_stringify(isa));

			/* verify the far max ifp can be calculated. this requires far max datagram to be set. */
			if (!ast_udptl_get_far_max_datagram(p->udptl)) {
				/* setting to zero will force a default if none was provided by the SDP */
				ast_udptl_set_far_max_datagram(p->udptl, 0);
			}

			/* Remote party offers T38, we need to update state */
			if ((t38action == SDP_T38_ACCEPT) &&
			    (p->t38.state == T38_LOCAL_REINVITE)) {
				change_t38_state(p, T38_ENABLED);
			} else if ((t38action == SDP_T38_INITIATE) &&
				   p->owner && p->lastinvite) {
				change_t38_state(p, T38_PEER_REINVITE); /* T38 Offered in re-invite from remote party */
				/* If fax detection is enabled then send us off to the fax extension */
				if (ast_test_flag(&p->flags[1], SIP_PAGE2_FAX_DETECT_T38)) {
					ast_channel_lock(p->owner);
					if (strcmp(p->owner->exten, "fax")) {
						const char *target_context = S_OR(p->owner->macrocontext, p->owner->context);
						ast_channel_unlock(p->owner);
						if (ast_exists_extension(p->owner, target_context, "fax", 1,
							S_COR(p->owner->caller.id.number.valid, p->owner->caller.id.number.str, NULL))) {
							ast_verbose(VERBOSE_PREFIX_2 "Redirecting '%s' to fax extension due to peer T.38 re-INVITE\n", p->owner->name);
							pbx_builtin_setvar_helper(p->owner, "FAXEXTEN", p->owner->exten);
							if (ast_async_goto(p->owner, target_context, "fax", 1)) {
								ast_log(LOG_NOTICE, "Failed to async goto '%s' into fax of '%s'\n", p->owner->name, target_context);
							}
						} else {
							ast_log(LOG_NOTICE, "T.38 re-INVITE detected but no fax extension\n");
						}
					} else {
						ast_channel_unlock(p->owner);
					}
				}
			}
		} else {
			change_t38_state(p, T38_DISABLED);
			ast_udptl_stop(p->udptl);
			if (debug)
				ast_debug(1, "Peer doesn't provide T.38 UDPTL\n");
		}
	}

	if ((portno == -1) && (p->t38.state != T38_DISABLED) && (p->t38.state != T38_REJECTED)) {
		ast_debug(3, "Have T.38 but no audio, accepting offer anyway\n");
		res = 0;
		goto process_sdp_cleanup;
	}

	/* Ok, we're going with this offer */
	ast_debug(2, "We're settling with these formats: %s\n", ast_getformatname_multiple(buf, SIPBUFSIZE, p->jointcaps));

	if (!p->owner) { /* There's no open channel owning us so we can return here. For a re-invite or so, we proceed */
		res = 0;
		goto process_sdp_cleanup;
	}

	ast_debug(4, "We have an owner, now see if we need to change this call\n");
	if (ast_format_cap_has_type(p->jointcaps, AST_FORMAT_TYPE_AUDIO)) {
		if (debug) {
			char s1[SIPBUFSIZE], s2[SIPBUFSIZE];
			ast_debug(1, "Setting native formats after processing SDP. peer joint formats %s, old nativeformats %s\n",
				ast_getformatname_multiple(s1, SIPBUFSIZE, p->jointcaps),
				ast_getformatname_multiple(s2, SIPBUFSIZE, p->owner->nativeformats));
		}

		ast_codec_choose(&p->prefs, p->jointcaps, 1, &tmp_fmt);

		ast_format_cap_set(p->owner->nativeformats, &tmp_fmt);
		ast_format_cap_joint_append(p->caps, vpeercapability, p->owner->nativeformats);
		ast_format_cap_joint_append(p->caps, tpeercapability, p->owner->nativeformats);

		ast_set_read_format(p->owner, &p->owner->readformat);
		ast_set_write_format(p->owner, &p->owner->writeformat);
	}

	if (ast_test_flag(&p->flags[1], SIP_PAGE2_CALL_ONHOLD) && (!ast_sockaddr_isnull(sa) || !ast_sockaddr_isnull(vsa) || !ast_sockaddr_isnull(tsa) || !ast_sockaddr_isnull(isa)) && (!sendonly || sendonly == -1)) {
		ast_queue_control(p->owner, AST_CONTROL_UNHOLD);
		/* Activate a re-invite */
		ast_queue_frame(p->owner, &ast_null_frame);
		change_hold_state(p, req, FALSE, sendonly);
	} else if ((sockaddr_is_null_or_any(sa) && sockaddr_is_null_or_any(vsa) && sockaddr_is_null_or_any(tsa) && sockaddr_is_null_or_any(isa)) || (sendonly && sendonly != -1)) {
		ast_queue_control_data(p->owner, AST_CONTROL_HOLD,
				       S_OR(p->mohsuggest, NULL),
				       !ast_strlen_zero(p->mohsuggest) ? strlen(p->mohsuggest) + 1 : 0);
		if (sendonly)
			ast_rtp_instance_stop(p->rtp);
		/* RTCP needs to go ahead, even if we're on hold!!! */
		/* Activate a re-invite */
		ast_queue_frame(p->owner, &ast_null_frame);
		change_hold_state(p, req, TRUE, sendonly);
	}

process_sdp_cleanup:
	ast_format_cap_destroy(peercapability);
	ast_format_cap_destroy(vpeercapability);
	ast_format_cap_destroy(tpeercapability);
	ast_format_cap_destroy(newjointcapability);
	ast_format_cap_destroy(newpeercapability);
	return res;
}
