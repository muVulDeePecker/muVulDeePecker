static void CVE_2012_3553_VULN_setsubstate(struct skinny_subchannel *sub, int state)
{
	struct skinny_line *l = sub->line;
	struct skinny_subline *subline = sub->subline;
	struct skinny_device *d = l->device;
	struct ast_channel *c = sub->owner;
	pthread_t t;
	int actualstate = state;

	if (sub->substate == SUBSTATE_ONHOOK) {
		return;
	}

	if (state != SUBSTATE_RINGIN && sub->aa_sched) {
		skinny_sched_del(sub->aa_sched);
		sub->aa_sched = 0;
		sub->aa_beep = 0;
		sub->aa_mute = 0;
	}
	
	if ((state == SUBSTATE_RINGIN) && ((d->hookstate == SKINNY_OFFHOOK) || (AST_LIST_NEXT(AST_LIST_FIRST(&l->sub), list)))) {
		actualstate = SUBSTATE_CALLWAIT;
	}

	if ((state == SUBSTATE_CONNECTED) && (!subline) && (AST_LIST_FIRST(&l->sublines))) {
		const char *slastation;
		struct skinny_subline *tmpsubline;
		slastation = pbx_builtin_getvar_helper(c, "SLASTATION");
		ast_verb(3, "Connecting %s to subline\n", slastation);
		if (slastation) {
			AST_LIST_TRAVERSE(&l->sublines, tmpsubline, list) {
				if (!strcasecmp(tmpsubline->stname, slastation)) {
					subline = tmpsubline;
					break;
				}
			}
			if (subline) {
				struct skinny_line *tmpline;
				subline->sub = sub;
				sub->subline = subline;
				subline->callid = sub->callid;
				send_callinfo(sub);
				AST_LIST_TRAVERSE(&lines, tmpline, all) {
					AST_LIST_TRAVERSE(&tmpline->sublines, tmpsubline, list) {
						if (!(subline == tmpsubline)) {
							if (!strcasecmp(subline->lnname, tmpsubline->lnname)) {
								tmpsubline->callid = callnums++;
								transmit_callstate(tmpsubline->line->device, tmpsubline->line->instance, tmpsubline->callid, SKINNY_OFFHOOK);
								push_callinfo(tmpsubline, sub);
								skinny_extensionstate_cb(NULL, NULL, tmpsubline->extenstate, tmpsubline->container);
							}
						}
					}
				}
			}
		}
	}

	if (subline) { /* Different handling for subs under a subline, indications come through hints */
		switch (actualstate) {
		case SUBSTATE_ONHOOK:
			AST_LIST_REMOVE(&l->sub, sub, list);
			if (sub->related) {
				sub->related->related = NULL;
			}

			if (sub == l->activesub) {
				l->activesub = NULL;
				transmit_closereceivechannel(d, sub);
				transmit_stopmediatransmission(d, sub);
			}
			
			if (subline->callid) {
				transmit_stop_tone(d, l->instance, sub->callid);
				transmit_callstate(d, l->instance, subline->callid, SKINNY_CALLREMOTEMULTILINE);
				transmit_selectsoftkeys(d, l->instance, subline->callid, KEYDEF_SLACONNECTEDNOTACTIVE);
				transmit_displaypromptstatus(d, "In Use", 0, l->instance, subline->callid);
			}
			
			sub->cxmode = SKINNY_CX_RECVONLY;	
			sub->substate = SUBSTATE_ONHOOK;
			if (sub->rtp) {
				ast_rtp_instance_destroy(sub->rtp);
				sub->rtp = NULL;
			}
			sub->substate = SUBSTATE_ONHOOK;
			if (sub->owner) {
				ast_queue_hangup(sub->owner);
			}
			return;
		case SUBSTATE_CONNECTED:
			transmit_activatecallplane(d, l);
			transmit_stop_tone(d, l->instance, sub->callid);
			transmit_selectsoftkeys(d, l->instance, subline->callid, KEYDEF_CONNECTED);
			transmit_callstate(d, l->instance, subline->callid, SKINNY_CONNECTED);
			if (!sub->rtp) {
				start_rtp(sub);
			}
			if (sub->substate == SUBSTATE_RINGIN || sub->substate == SUBSTATE_CALLWAIT) {
				ast_queue_control(sub->owner, AST_CONTROL_ANSWER);
			}
			if (sub->substate == SUBSTATE_DIALING || sub->substate == SUBSTATE_RINGOUT) {
				transmit_dialednumber(d, l->lastnumberdialed, l->instance, sub->callid);
			}
			if (sub->owner->_state != AST_STATE_UP) {
				ast_setstate(sub->owner, AST_STATE_UP);
			}
			sub->substate = SUBSTATE_CONNECTED;
			l->activesub = sub;
			return; 
		case SUBSTATE_HOLD:
			if (sub->substate != SUBSTATE_CONNECTED) {
				ast_log(LOG_WARNING, "Cannot set substate to SUBSTATE_HOLD from %s (on call-%d)\n", substate2str(sub->substate), sub->callid);
				return;
			}
			transmit_activatecallplane(d, l);
			transmit_closereceivechannel(d, sub);
			transmit_stopmediatransmission(d, sub);

			transmit_callstate(d, l->instance, subline->callid, SKINNY_CALLREMOTEMULTILINE);
			transmit_selectsoftkeys(d, l->instance, subline->callid, KEYDEF_SLACONNECTEDNOTACTIVE);
			transmit_displaypromptstatus(d, "In Use", 0, l->instance, subline->callid);
			
			sub->substate = SUBSTATE_HOLD;

			ast_queue_control_data(sub->owner, AST_CONTROL_HOLD,
				S_OR(l->mohsuggest, NULL),
				!ast_strlen_zero(l->mohsuggest) ? strlen(l->mohsuggest) + 1 : 0);

			return;
		default:
			ast_log(LOG_WARNING, "Substate handling under subline for state %d not implemented on Sub-%d\n", state, sub->callid);
		}
	}

	if ((d->hookstate == SKINNY_ONHOOK) && ((actualstate == SUBSTATE_OFFHOOK) || (actualstate == SUBSTATE_DIALING)
		|| (actualstate == SUBSTATE_RINGOUT) || (actualstate == SUBSTATE_CONNECTED) || (actualstate == SUBSTATE_BUSY)
		|| (actualstate == SUBSTATE_CONGESTION) || (actualstate == SUBSTATE_PROGRESS))) {
			d->hookstate = SKINNY_OFFHOOK;
			transmit_speaker_mode(d, SKINNY_SPEAKERON);
	}

	if (skinnydebug) {
		ast_verb(3, "Sub %d - change state from %s to %s\n", sub->callid, substate2str(sub->substate), substate2str(actualstate));
	}

	if (actualstate == sub->substate) {
		send_callinfo(sub);
		transmit_callstate(d, l->instance, sub->callid, SKINNY_HOLD);
		return;
	}

	switch (actualstate) {
	case SUBSTATE_OFFHOOK:
		ast_verb(1, "Call-id: %d\n", sub->callid);
		l->activesub = sub;
		transmit_callstate(d, l->instance, sub->callid, SKINNY_OFFHOOK);
		transmit_activatecallplane(d, l);
		transmit_clear_display_message(d, l->instance, sub->callid);
		transmit_start_tone(d, SKINNY_DIALTONE, l->instance, sub->callid);
		transmit_selectsoftkeys(d, l->instance, sub->callid, KEYDEF_OFFHOOK);
		transmit_displaypromptstatus(d, "Enter number", 0, l->instance, sub->callid);

		sub->substate = SUBSTATE_OFFHOOK;
	
		/* start the switch thread */
		if (ast_pthread_create(&t, NULL, skinny_ss, sub->owner)) {
			ast_log(LOG_WARNING, "Unable to create switch thread: %s\n", strerror(errno));
			ast_hangup(sub->owner);
		}
		break;
	case SUBSTATE_ONHOOK:
		AST_LIST_REMOVE(&l->sub, sub, list);
		if (sub->related) {
			sub->related->related = NULL;
		}

		if (sub == l->activesub) {
			l->activesub = NULL;
			transmit_closereceivechannel(d, sub);
			transmit_stopmediatransmission(d, sub);
			transmit_stop_tone(d, l->instance, sub->callid);
			transmit_callstate(d, l->instance, sub->callid, SKINNY_ONHOOK);
			transmit_clearpromptmessage(d, l->instance, sub->callid);
			transmit_ringer_mode(d, SKINNY_RING_OFF);
			transmit_definetimedate(d); 
			transmit_lamp_indication(d, STIMULUS_LINE, l->instance, SKINNY_LAMP_OFF);
		} else {
			transmit_stop_tone(d, l->instance, sub->callid);
			transmit_callstate(d, l->instance, sub->callid, SKINNY_ONHOOK);
			transmit_clearpromptmessage(d, l->instance, sub->callid);
		}

		sub->cxmode = SKINNY_CX_RECVONLY;	
		sub->substate = SUBSTATE_ONHOOK;
		if (sub->rtp) {
			ast_rtp_instance_destroy(sub->rtp);
			sub->rtp = NULL;
		}
		if (sub->owner) {
			ast_queue_hangup(sub->owner);
		}
		break;
	case SUBSTATE_DIALING:
		if (ast_strlen_zero(sub->exten) || !ast_exists_extension(c, c->context, sub->exten, 1, l->cid_num)) {
			ast_log(LOG_WARNING, "Exten (%s)@(%s) does not exist, unable to set substate DIALING on sub %d\n", sub->exten, c->context, sub->callid);
			return;
		}

		if (d->hookstate == SKINNY_ONHOOK) {
			d->hookstate = SKINNY_OFFHOOK;
			transmit_speaker_mode(d, SKINNY_SPEAKERON);
			transmit_activatecallplane(d, l);
		}

		if (!sub->subline) {
			transmit_callstate(d, l->instance, sub->callid, SKINNY_OFFHOOK);
			transmit_stop_tone(d, l->instance, sub->callid);
			transmit_clear_display_message(d, l->instance, sub->callid);
			transmit_selectsoftkeys(d, l->instance, sub->callid, KEYDEF_RINGOUT);
			transmit_displaypromptstatus(d, "Dialing", 0, l->instance, sub->callid);
		}

		if  (AST_LIST_FIRST(&l->sublines)) {
			if (subline) {
				ast_copy_string(c->exten, subline->exten, sizeof(c->exten));
				ast_copy_string(c->context, "sla_stations", sizeof(c->context));
			} else {
				pbx_builtin_setvar_helper(c, "_DESTEXTEN", sub->exten);
				pbx_builtin_setvar_helper(c, "_DESTCONTEXT", c->context);
				ast_copy_string(c->exten, l->dialoutexten, sizeof(c->exten));
				ast_copy_string(c->context, l->dialoutcontext, sizeof(c->context));
				ast_copy_string(l->lastnumberdialed, sub->exten, sizeof(l->lastnumberdialed));
			}
		} else {
			ast_copy_string(c->exten, sub->exten, sizeof(c->exten));
			ast_copy_string(l->lastnumberdialed, sub->exten, sizeof(l->lastnumberdialed));
		}
		
		sub->substate = SUBSTATE_DIALING;
	
		if (ast_pthread_create(&t, NULL, skinny_newcall, c)) {
			ast_log(LOG_WARNING, "Unable to create new call thread: %s\n", strerror(errno));
			ast_hangup(c);
		}
		break;
	case SUBSTATE_RINGOUT:
		if (!(sub->substate == SUBSTATE_DIALING || sub->substate == SUBSTATE_PROGRESS)) {
			ast_log(LOG_WARNING, "Cannot set substate to SUBSTATE_RINGOUT from %s (on call-%d)\n", substate2str(sub->substate), sub->callid);
			return;
		}
	
		if (!d->earlyrtp) {
			transmit_start_tone(d, SKINNY_ALERT, l->instance, sub->callid);
		}
		transmit_callstate(d, l->instance, sub->callid, SKINNY_RINGOUT);
		transmit_dialednumber(d, l->lastnumberdialed, l->instance, sub->callid);
		transmit_displaypromptstatus(d, "Ring Out", 0, l->instance, sub->callid);
		send_callinfo(sub);
		sub->substate = SUBSTATE_RINGOUT;
		break;
	case SUBSTATE_RINGIN:
		transmit_callstate(d, l->instance, sub->callid, SKINNY_RINGIN);
		transmit_selectsoftkeys(d, l->instance, sub->callid, KEYDEF_RINGIN);
		transmit_displaypromptstatus(d, "Ring-In", 0, l->instance, sub->callid);
		send_callinfo(sub);
		transmit_lamp_indication(d, STIMULUS_LINE, l->instance, SKINNY_LAMP_BLINK);
		transmit_ringer_mode(d, SKINNY_RING_INSIDE);
		transmit_activatecallplane(d, l);

		if (d->hookstate == SKINNY_ONHOOK) {
			l->activesub = sub;
		}
	
		if (sub->substate != SUBSTATE_RINGIN || sub->substate != SUBSTATE_CALLWAIT) {
			ast_setstate(c, AST_STATE_RINGING);
			ast_queue_control(c, AST_CONTROL_RINGING);
		}
		sub->substate = SUBSTATE_RINGIN;
		break;
	case SUBSTATE_CALLWAIT:
		transmit_callstate(d, l->instance, sub->callid, SKINNY_RINGIN);
		transmit_callstate(d, l->instance, sub->callid, SKINNY_CALLWAIT);
		transmit_selectsoftkeys(d, l->instance, sub->callid, KEYDEF_RINGIN);
		transmit_displaypromptstatus(d, "Callwaiting", 0, l->instance, sub->callid);
		send_callinfo(sub);
		transmit_lamp_indication(d, STIMULUS_LINE, l->instance, SKINNY_LAMP_BLINK);
		transmit_start_tone(d, SKINNY_CALLWAITTONE, l->instance, sub->callid);
	
		ast_setstate(c, AST_STATE_RINGING);
		ast_queue_control(c, AST_CONTROL_RINGING);
		sub->substate = SUBSTATE_CALLWAIT;
		break;
	case SUBSTATE_CONNECTED:
		if (sub->substate == SUBSTATE_HOLD) {
			ast_queue_control(sub->owner, AST_CONTROL_UNHOLD);
			transmit_connect(d, sub);
		}
		transmit_ringer_mode(d, SKINNY_RING_OFF);
		transmit_activatecallplane(d, l);
		transmit_stop_tone(d, l->instance, sub->callid);
		send_callinfo(sub);
		transmit_callstate(d, l->instance, sub->callid, SKINNY_CONNECTED);
		transmit_displaypromptstatus(d, "Connected", 0, l->instance, sub->callid);
		transmit_selectsoftkeys(d, l->instance, sub->callid, KEYDEF_CONNECTED);
		if (!sub->rtp) {
			start_rtp(sub);
		}
		if (sub->aa_beep) {
			transmit_start_tone(d, SKINNY_ZIP, l->instance, sub->callid);
		}
		if (sub->aa_mute) {
			transmit_microphone_mode(d, SKINNY_MICOFF);
		}
		if (sub->substate == SUBSTATE_RINGIN || sub->substate == SUBSTATE_CALLWAIT) {
			ast_queue_control(sub->owner, AST_CONTROL_ANSWER);
		}
		if (sub->substate == SUBSTATE_DIALING || sub->substate == SUBSTATE_RINGOUT) {
			transmit_dialednumber(d, l->lastnumberdialed, l->instance, sub->callid);
		}
		if (sub->owner->_state != AST_STATE_UP) {
			ast_setstate(sub->owner, AST_STATE_UP);
		}
		sub->substate = SUBSTATE_CONNECTED;
		l->activesub = sub;
		break;
	case SUBSTATE_BUSY:
		if (!(sub->substate == SUBSTATE_DIALING || sub->substate == SUBSTATE_PROGRESS || sub->substate == SUBSTATE_RINGOUT)) {
			ast_log(LOG_WARNING, "Cannot set substate to SUBSTATE_BUSY from %s (on call-%d)\n", substate2str(sub->substate), sub->callid);
			return;
		}

		if (!d->earlyrtp) {
			transmit_start_tone(d, SKINNY_BUSYTONE, l->instance, sub->callid);
		}
		send_callinfo(sub);
		transmit_callstate(d, l->instance, sub->callid, SKINNY_BUSY);
		transmit_displaypromptstatus(d, "Busy", 0, l->instance, sub->callid);
		sub->substate = SUBSTATE_BUSY;
		break;
	case SUBSTATE_CONGESTION:
		if (!(sub->substate == SUBSTATE_DIALING || sub->substate == SUBSTATE_PROGRESS || sub->substate == SUBSTATE_RINGOUT)) {
			ast_log(LOG_WARNING, "Cannot set substate to SUBSTATE_CONGESTION from %s (on call-%d)\n", substate2str(sub->substate), sub->callid);
			return;
		}

		if (!d->earlyrtp) {
			transmit_start_tone(d, SKINNY_REORDER, l->instance, sub->callid);
		}
		send_callinfo(sub);
		transmit_callstate(d, l->instance, sub->callid, SKINNY_CONGESTION);
		transmit_displaypromptstatus(d, "Congestion", 0, l->instance, sub->callid);
		sub->substate = SUBSTATE_CONGESTION;
		break;
	case SUBSTATE_PROGRESS:
		if (sub->substate != SUBSTATE_DIALING) {
			ast_log(LOG_WARNING, "Cannot set substate to SUBSTATE_PROGRESS from %s (on call-%d)\n", substate2str(sub->substate), sub->callid);
			return;
		}

		if (!d->earlyrtp) {
			transmit_start_tone(d, SKINNY_ALERT, l->instance, sub->callid);
		}
		send_callinfo(sub);
		transmit_callstate(d, l->instance, sub->callid, SKINNY_PROGRESS);
		transmit_displaypromptstatus(d, "Call Progress", 0, l->instance, sub->callid);
		sub->substate = SUBSTATE_PROGRESS;
		break;
	case SUBSTATE_HOLD:
		if (sub->substate != SUBSTATE_CONNECTED) {
			ast_log(LOG_WARNING, "Cannot set substate to SUBSTATE_HOLD from %s (on call-%d)\n", substate2str(sub->substate), sub->callid);
			return;
		}
		ast_queue_control_data(sub->owner, AST_CONTROL_HOLD,
			S_OR(l->mohsuggest, NULL),
			!ast_strlen_zero(l->mohsuggest) ? strlen(l->mohsuggest) + 1 : 0);

		transmit_activatecallplane(d, l);
		transmit_closereceivechannel(d, sub);
		transmit_stopmediatransmission(d, sub);

		transmit_callstate(d, l->instance, sub->callid, SKINNY_HOLD);
		transmit_lamp_indication(d, STIMULUS_LINE, l->instance, SKINNY_LAMP_WINK);
		transmit_selectsoftkeys(d, l->instance, sub->callid, KEYDEF_ONHOLD);
		sub->substate = SUBSTATE_HOLD;
		break;
	default:
		ast_log(LOG_WARNING, "Was asked to change to nonexistant substate %d on Sub-%d\n", state, sub->callid);
	}
}
