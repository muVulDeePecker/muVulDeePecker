static void
CVE_2012_6061_VULN_dissect_wtp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    char *szInfo;
    int			offCur		= 0;   /* current offset from start of WTP data */
    gint		returned_length, str_index = 0;

    unsigned char	b0;

    /* continuation flag */
    unsigned char  	fCon;			/* Continue flag	*/
    unsigned char  	fRID;			/* Re-transmission indicator*/
    unsigned char  	fTTR = '\0';		/* Transmission trailer	*/
    guint 		cbHeader   	= 0;	/* Fixed header length	*/
    guint 		vHeader   	= 0;	/* Variable header length*/
    int 		abortType  	= 0;

    /* Set up structures we'll need to add the protocol subtree and manage it */
    proto_item		*ti = NULL;
    proto_tree		*wtp_tree = NULL;

    char		pdut;
    char		clsTransaction = 3;
    int			numMissing = 0;		/* Number of missing packets in a negative ack */
    int			i;
    tvbuff_t		*wsp_tvb = NULL;
    guint8		psn = 0;		/* Packet sequence number*/
    guint16		TID = 0;		/* Transaction-Id	*/
    int			dataOffset;
    gint		dataLen;

#define SZINFO_SIZE 256
    szInfo=ep_alloc(SZINFO_SIZE);

    b0 = tvb_get_guint8 (tvb, offCur + 0);
    /* Discover Concatenated PDUs */
    if (b0 == 0) {
	guint	c_fieldlen = 0;		/* Length of length-field	*/
	guint	c_pdulen = 0;		/* Length of conc. PDU	*/

	if (tree) {
	    ti = proto_tree_add_item(tree, proto_wtp,
				    tvb, offCur, 1, ENC_NA);
	    wtp_tree = proto_item_add_subtree(ti, ett_wtp_sub_pdu_tree);
		proto_item_append_text(ti, ", PDU concatenation");
	}
	offCur = 1;
	i = 1;
	while (offCur < (int) tvb_reported_length(tvb)) {
	    tvbuff_t *wtp_tvb;
	    /* The length of an embedded WTP PDU is coded as either:
	     *	- a 7-bit value contained in one octet with highest bit == 0.
	     *	- a 15-bit value contained in two octets (little endian)
	     *	  if the 1st octet has its highest bit == 1.
	     * This means that this is NOT encoded as an uintvar-integer!!!
	     */
	    b0 = tvb_get_guint8(tvb, offCur + 0);
	    if (b0 & 0x80) {
		c_fieldlen = 2;
		c_pdulen = ((b0 & 0x7f) << 8) | tvb_get_guint8(tvb, offCur + 1);
	    } else {
		c_fieldlen = 1;
		c_pdulen = b0;
	    }
	    if (tree) {
		proto_tree_add_uint(wtp_tree, hf_wtp_header_sub_pdu_size,
				    tvb, offCur, c_fieldlen, c_pdulen);
	    }
	    if (i > 1) {
		col_append_str(pinfo->cinfo, COL_INFO, ", ");
	    }
	    /* Skip the length field for the WTP sub-tvb */
	    wtp_tvb = tvb_new_subset(tvb, offCur + c_fieldlen, c_pdulen, c_pdulen);
	    CVE_2012_6061_VULN_dissect_wtp_common(wtp_tvb, pinfo, wtp_tree);
	    offCur += c_fieldlen + c_pdulen;
	    i++;
	}
	if (tree) {
		proto_item_append_text(ti, ", PDU count: %u", i);
	}
	return;
    }
    /* No concatenation */
    fCon = b0 & 0x80;
    fRID = retransmission_indicator(b0);
    pdut = pdu_type(b0);

#ifdef DEBUG
	printf("WTP packet %u: tree = %p, pdu = %s (%u) length: %u\n",
			pinfo->fd->num, tree,
			val_to_str(pdut, vals_wtp_pdu_type, "Unknown PDU type 0x%x"),
			pdut, tvb_length(tvb));
#endif

    /* Develop the string to put in the Info column */
    returned_length =  g_snprintf(szInfo, SZINFO_SIZE, "WTP %s",
		    val_to_str(pdut, vals_wtp_pdu_type, "Unknown PDU type 0x%x"));
    str_index += MIN(returned_length, SZINFO_SIZE-str_index);

    switch (pdut) {
	case INVOKE:
	    fTTR = transmission_trailer(b0);
	    TID = tvb_get_ntohs(tvb, offCur + 1);
	    psn = 0;
	    clsTransaction = transaction_class(tvb_get_guint8(tvb, offCur + 3));
	    returned_length = g_snprintf(&szInfo[str_index], SZINFO_SIZE-str_index,
		" Class %d", clsTransaction);
            str_index += MIN(returned_length, SZINFO_SIZE-str_index);
	    cbHeader = 4;
	    break;

	case SEGMENTED_INVOKE:
	case SEGMENTED_RESULT:
	    fTTR = transmission_trailer(b0);
	    TID = tvb_get_ntohs(tvb, offCur + 1);
	    psn = tvb_get_guint8(tvb, offCur + 3);
	    if (psn != 0) {
		returned_length = g_snprintf(&szInfo[str_index], SZINFO_SIZE-str_index,
			" (%u)", psn);
                str_index += MIN(returned_length, SZINFO_SIZE-str_index);
	    }
	    cbHeader = 4;
	    break;

	case ABORT:
	    cbHeader = 4;
	    break;

	case RESULT:
	    fTTR = transmission_trailer(b0);
	    TID = tvb_get_ntohs(tvb, offCur + 1);
	    psn = 0;
	    cbHeader = 3;
	    break;

	case ACK:
	    cbHeader = 3;
	    break;

	case NEGATIVE_ACK:
	    /* Variable number of missing packets */
	    numMissing = tvb_get_guint8(tvb, offCur + 3);
	    cbHeader = numMissing + 4;
	    break;

	default:
	    break;
    };
    if (fRID) {
	returned_length = g_snprintf(&szInfo[str_index], SZINFO_SIZE-str_index, " R" );
        str_index += MIN(returned_length, SZINFO_SIZE-str_index);
    };
    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: cbHeader = %d\n", cbHeader);
#endif
	/* NOTE - Length will be set when we process the TPI */
	ti = proto_tree_add_item(tree, proto_wtp, tvb, offCur, 0, ENC_NA);
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: (7) Returned from proto_tree_add_item\n");
#endif
	wtp_tree = proto_item_add_subtree(ti, ett_wtp);

/* Code to process the packet goes here */
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: cbHeader = %d\n", cbHeader);
	fprintf(stderr, "dissect_wtp: offCur = %d\n", offCur);
#endif
	/* Add common items: only CON and PDU Type */
	proto_tree_add_item(
			wtp_tree,	 		/* tree */
			hf_wtp_header_flag_continue, 	/* id */
			tvb,
			offCur, 			/* start of highlight */
			1,				/* length of highlight*/
			b0				/* value */
	     );
	proto_tree_add_item(wtp_tree, hf_wtp_header_pdu_type, tvb, offCur, 1, ENC_LITTLE_ENDIAN);

	switch(pdut) {
	    case INVOKE:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_version , tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_flag_TIDNew, tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_flag_UP, tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_Reserved, tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_Inv_TransactionClass, tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti,
				", PDU: Invoke (%u)"
				", Transaction Class: %s (%u)",
				INVOKE,
				val_to_str(clsTransaction, vals_transaction_classes, "Undefined"),
				clsTransaction);
		break;

	    case RESULT:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_item_append_text(ti, ", PDU: Result (%u)", RESULT);
		break;

	    case ACK:
		proto_tree_add_item(wtp_tree, hf_wtp_header_Ack_flag_TVETOK, tvb, offCur, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_item_append_text(ti, ", PDU: ACK (%u)", ACK);
		break;

	    case ABORT:
		abortType = tvb_get_guint8 (tvb, offCur) & 0x07;
		proto_tree_add_item(wtp_tree, hf_wtp_header_Abort_type , tvb, offCur , 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);

		if (abortType == PROVIDER)
		{
			guint8 reason = tvb_get_guint8(tvb, offCur + 3);
		    proto_tree_add_item( wtp_tree, hf_wtp_header_Abort_reason_provider , tvb, offCur + 3 , 1, ENC_LITTLE_ENDIAN);
			proto_item_append_text(ti,
					", PDU: Abort (%u)"
					", Type: Provider (%u)"
					", Reason: %s (%u)",
					ABORT,
					PROVIDER,
					val_to_str(reason, vals_abort_reason_provider, "Undefined"),
					reason);
		}
		else if (abortType == USER)
		{
			guint8 reason = tvb_get_guint8(tvb, offCur + 3);
		    proto_tree_add_item(wtp_tree, hf_wtp_header_Abort_reason_user , tvb, offCur + 3 , 1, ENC_LITTLE_ENDIAN);
			proto_item_append_text(ti,
					", PDU: Abort (%u)"
					", Type: User (%u)"
					", Reason: %s (%u)",
					ABORT,
					PROVIDER,
					val_to_str_ext_const(reason, &vals_wsp_reason_codes_ext, "Undefined"),
					reason);
		}
		break;

	    case SEGMENTED_INVOKE:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(wtp_tree, hf_wtp_header_sequence_number , tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti,
				", PDU: Segmented Invoke (%u)"
				", Packet Sequence Number: %u",
				SEGMENTED_INVOKE, psn);
		break;

	    case SEGMENTED_RESULT:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_Trailer, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(wtp_tree, hf_wtp_header_sequence_number , tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(ti,
				", PDU: Segmented Result (%u)"
				", Packet Sequence Number: %u",
				SEGMENTED_RESULT, psn);
		break;

	    case NEGATIVE_ACK:
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_RID, tvb, offCur, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID_response, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wtp_tree, hf_wtp_header_flag_TID, tvb, offCur + 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(wtp_tree, hf_wtp_header_missing_packets , tvb, offCur + 3, 1, ENC_LITTLE_ENDIAN);
		/* Iterate through missing packets */
		for (i = 0; i < numMissing; i++)
		{
		    proto_tree_add_item(wtp_tree, hf_wtp_header_sequence_number, tvb, offCur + 4 + i, 1, ENC_LITTLE_ENDIAN);
		}
		proto_item_append_text(ti,
				", PDU: Negative Ack (%u)"
				", Missing Packets: %u",
				NEGATIVE_ACK, numMissing);
		break;

	    default:
		break;
	};
	if (fRID) {
		proto_item_append_text(ti, ", Retransmission");
	}
    } else { /* tree is NULL */
#ifdef DEBUG
	fprintf(stderr, "dissect_wtp: (4) tree was %p\n", tree);
#endif
    }
	/* Process the variable part */
	if (fCon) {			/* Now, analyze variable part	*/
	    unsigned char	 tCon;
	    unsigned char	 tByte;
	    unsigned char	 tpiLen;
	    tvbuff_t		*tmp_tvb;

	    vHeader = 0;		/* Start scan all over	*/

	    do {
		tByte = tvb_get_guint8(tvb, offCur + cbHeader + vHeader);
		tCon = tByte & 0x80;
		if (tByte & 0x04)	/* Long TPI	*/
		    tpiLen = 2 + tvb_get_guint8(tvb,
					    offCur + cbHeader + vHeader + 1);
		else
		    tpiLen = 1 + (tByte & 0x03);
		if (tree)
		{
		tmp_tvb = tvb_new_subset(tvb, offCur + cbHeader + vHeader,
					tpiLen, tpiLen);
		wtp_handle_tpi(wtp_tree, tmp_tvb);
		}
		vHeader += tpiLen;
	    } while (tCon);
	} else {
		/* There is no variable part */
	}	/* End of variable part of header */

	/* Set the length of the WTP protocol part now we know the length of the
	 * fixed and variable WTP headers */
	if (tree)
	proto_item_set_len(ti, cbHeader + vHeader);

#ifdef DEBUG
    fprintf( stderr, "dissect_wtp: cbHeader = %d\n", cbHeader );
#endif

    /*
     * Any remaining data ought to be WSP data (if not WTP ACK, NACK
     * or ABORT pdu), so, if we have any remaining data, and it's
     * not an ACK, NACK, or ABORT PDU, hand it off (defragmented) to the
     * WSP dissector.
     * Note that the last packet of a fragmented WTP message needn't
     * contain any data, so we allow payloadless packets to be
     * reassembled.  (XXX - does the reassembly code handle this
     * for packets other than the last packet?)
     *
	 * Try calling a subdissector only if:
	 *	- The WTP payload is ressembled in this very packet,
	 *	- The WTP payload is not fragmented across packets.
	 */
    dataOffset = offCur + cbHeader + vHeader;
    dataLen = tvb_reported_length_remaining(tvb, dataOffset);
    if ((dataLen >= 0) &&
			! ((pdut==ACK) || (pdut==NEGATIVE_ACK) || (pdut==ABORT)))
    {
		/* Try to reassemble if needed, and hand over to WSP
		 * A fragmented WTP packet is either:
		 *	- An INVOKE with fTTR (transmission trailer) not set,
		 *	- a SEGMENTED_INVOKE,
		 *	- A RESULT with fTTR (transmission trailer) not set,
		 *	- a SEGMENTED_RESULT.
		 */
		if ( ( (pdut == SEGMENTED_INVOKE) || (pdut == SEGMENTED_RESULT)
				|| ( ((pdut == INVOKE) || (pdut == RESULT)) && (!fTTR) )
			) && tvb_bytes_exist(tvb, dataOffset, dataLen) )
		{
			/* Try reassembling fragments */
			fragment_data *fd_wtp = NULL;
			guint32 reassembled_in = 0;
			gboolean save_fragmented = pinfo->fragmented;

			pinfo->fragmented = TRUE;
			fd_wtp = fragment_add_seq(tvb, dataOffset, pinfo, TID,
					wtp_fragment_table, psn, dataLen, !fTTR);
			/* XXX - fragment_add_seq() yields NULL unless Wireshark knows
			 * that the packet is part of a reassembled whole. This means
			 * that fd_wtp will be NULL as long as Wireshark did not encounter
			 * (and process) the packet containing the last fragment.
			 * This implies that Wireshark needs two passes over the data for
			 * correct reassembly. At the first pass, a capture containing
			 * three fragments plus a retransmssion of the last fragment
			 * will progressively show:
			 *
			 *		Packet 1: (Unreassembled fragment 1)
			 *		Packet 2: (Unreassembled fragment 2)
			 *		Packet 3: (Reassembled WTP)
			 *		Packet 4: (WTP payload reassembled in packet 3)
			 *
			 * However at subsequent evaluation (e.g., by applying a display
			 * filter) the packet summary will show:
			 *
			 *		Packet 1: (WTP payload reassembled in packet 3)
			 *		Packet 2: (WTP payload reassembled in packet 3)
			 *		Packet 3: (Reassembled WTP)
			 *		Packet 4: (WTP payload reassembled in packet 3)
			 *
			 * This is important to know, and also affects read filters!
			 */
			wsp_tvb = process_reassembled_data(tvb, dataOffset, pinfo,
					"Reassembled WTP", fd_wtp, &wtp_frag_items,
					NULL, wtp_tree);
#ifdef DEBUG
			printf("WTP: Packet %u %s -> %d: wsp_tvb = %p, fd_wtp = %p, frame = %u\n",
					pinfo->fd->num,
					fd_wtp ? "Reassembled" : "Not reassembled",
					fd_wtp ? fd_wtp->reassembled_in : -1,
					wsp_tvb,
					fd_wtp
					);
#endif
			if (fd_wtp) {
				/* Reassembled */
				reassembled_in = fd_wtp->reassembled_in;
				if (pinfo->fd->num == reassembled_in) {
					/* Reassembled in this very packet:
					 * We can safely hand the tvb to the WSP dissector */
					call_dissector(wsp_handle, wsp_tvb, pinfo, tree);
				} else {
					/* Not reassembled in this packet */
					if (check_col(pinfo->cinfo, COL_INFO)) {
						col_append_fstr(pinfo->cinfo, COL_INFO,
								"%s (WTP payload reassembled in packet %u)",
								szInfo, fd_wtp->reassembled_in);
					}
					if (tree) {
						proto_tree_add_text(wtp_tree, tvb, dataOffset, -1,
								"Payload");
					}
				}
			} else {
				/* Not reassembled yet, or not reassembled at all */
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(pinfo->cinfo, COL_INFO,
								"%s (Unreassembled fragment %u)",
								szInfo, psn);
				}
				if (tree) {
					proto_tree_add_text(wtp_tree, tvb, dataOffset, -1,
							"Payload");
				}
			}
			/* Now reset fragmentation information in pinfo */
			pinfo->fragmented = save_fragmented;
		}
		else if ( ((pdut == INVOKE) || (pdut == RESULT)) && (fTTR) )
		{
			/* Non-fragmented payload */
			wsp_tvb = tvb_new_subset_remaining(tvb, dataOffset);
			/* We can safely hand the tvb to the WSP dissector */
			call_dissector(wsp_handle, wsp_tvb, pinfo, tree);
		}
		else
		{
			/* Nothing to hand to subdissector */
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_str(pinfo->cinfo, COL_INFO, szInfo);
		}
	}
	else
	{
		/* Nothing to hand to subdissector */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO, szInfo);
	}
}
