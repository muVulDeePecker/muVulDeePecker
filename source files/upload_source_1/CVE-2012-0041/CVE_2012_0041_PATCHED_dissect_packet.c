void
CVE_2012_0041_PATCHED_dissect_packet(epan_dissect_t *edt, union wtap_pseudo_header *pseudo_header,
	       const guchar *pd, frame_data *fd, column_info *cinfo)
{
	if (cinfo != NULL)
		col_init(cinfo);
	memset(&edt->pi, 0, sizeof(edt->pi));
	edt->pi.current_proto = "<Missing Protocol Name>";
	edt->pi.cinfo = cinfo;
	edt->pi.fd = fd;
	edt->pi.pseudo_header = pseudo_header;
	edt->pi.dl_src.type = AT_NONE;
	edt->pi.dl_dst.type = AT_NONE;
	edt->pi.net_src.type = AT_NONE;
	edt->pi.net_dst.type = AT_NONE;
	edt->pi.src.type = AT_NONE;
	edt->pi.dst.type = AT_NONE;
	edt->pi.ctype = CT_NONE;
	edt->pi.noreassembly_reason = "";
	edt->pi.ptype = PT_NONE;
	edt->pi.p2p_dir = P2P_DIR_UNKNOWN;
	edt->pi.dcetransporttype = -1;
	edt->pi.annex_a_used = MTP2_ANNEX_A_USED_UNKNOWN;
	edt->pi.dcerpc_procedure_name="";
	edt->pi.link_dir = LINK_DIR_UNKNOWN;
	edt->tvb = NULL;

	/* to enable decode as for ethertype=0x0000 (fix for bug 4721) */
	edt->pi.ethertype = G_MAXINT;

	EP_CHECK_CANARY(("before dissecting frame %d",fd->num));

	TRY {
		/*
		 * XXX - currently, the length arguments to
		 * tvb_new_real_data() are signed, but the captured
		 * and reported length values are unsigned; this means
		 * that length values > 2^31 - 1 will appear as
		 * negative lengths in tvb_new_real_data().
		 *
		 * Captured length values that large will already
		 * have been filtered out by the Wiretap modules
		 * (the file will be reported as corrupted), to
		 * avoid trying to allocate large chunks of data.
		 *
		 * Reported length values will not have been
		 * filtered out, and should not be filtered out,
		 * as those lengths are not necessarily invalid.
		 *
		 * For now, we clip the reported length at G_MAXINT,
		 * so that tvb_new_real_data() doesn't fail.  It
		 * would throw an exception, which we'd catch, but
		 * that would mean we would have no tvbuffs
		 * associated with edt, which would upset much of
		 * the rest of the application.
		 */
		edt->tvb = tvb_new_real_data(pd, fd->cap_len,
		    fd->pkt_len > G_MAXINT ? G_MAXINT : fd->pkt_len);
		/* Add this tvbuffer into the data_src list */
		add_new_data_source(&edt->pi, edt->tvb, "Frame");

		/* Even though dissect_frame() catches all the exceptions a
		 * sub-dissector can throw, dissect_frame() itself may throw
		 * a ReportedBoundsError in bizarre cases. Thus, we catch the exception
		 * in this function. */
		if(frame_handle != NULL)
		  call_dissector(frame_handle, edt->tvb, &edt->pi, edt->tree);

	}
	CATCH(BoundsError) {
		g_assert_not_reached();
	}
	CATCH(ReportedBoundsError) {
		if(proto_malformed != -1){
			proto_tree_add_protocol_format(edt->tree, proto_malformed, edt->tvb, 0, 0,
						       "[Malformed Frame: Packet Length]" );
		} else {
			g_assert_not_reached();
		}
	}
	CATCH(OutOfMemoryError) {
		RETHROW;
	}
	ENDTRY;

	EP_CHECK_CANARY(("after dissecting frame %d",fd->num));

	fd->flags.visited = 1;
}
