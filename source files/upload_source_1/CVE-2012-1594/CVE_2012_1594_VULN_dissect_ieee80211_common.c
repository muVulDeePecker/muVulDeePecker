static void
CVE_2012_1594_VULN_dissect_ieee80211_common (tvbuff_t * tvb, packet_info * pinfo,
        proto_tree * tree, gboolean fixed_length_header, gint fcs_len,
        gboolean wlan_broken_fc, gboolean datapad,
        gboolean is_ht)
{
  guint16 fcf, flags, frame_type_subtype, ctrl_fcf, ctrl_type_subtype;
  guint16 seq_control;
  guint32 seq_number, frag_number;
  gboolean more_frags;
  const guint8 *src = NULL;
  const guint8 *dst = NULL;
  const guint8 *bssid = NULL;
  proto_item *ti = NULL;
  proto_item *fcs_item = NULL;
  proto_item *cw_item = NULL;
  proto_item *hidden_item;
  proto_tree *volatile hdr_tree = NULL;
  proto_tree *fcs_tree = NULL;
  proto_tree *cw_tree = NULL;
  guint16 hdr_len, ohdr_len, htc_len = 0;
  gboolean has_fcs, fcs_good, fcs_bad;
  gint len, reported_len, ivlen;
  gboolean is_amsdu = 0;
  gboolean save_fragmented;
  tvbuff_t *volatile next_tvb = NULL;
  guint32 addr_type;
  volatile encap_t encap_type;
  guint8 octet1, octet2;
  char out_buff[SHORT_STR];
  gint is_iv_bad;
  guchar iv_buff[4];
  const char *addr1_str = NULL;
  int addr1_hf = -1;
  guint offset;
  const gchar *fts_str;
  gchar flag_str[] = "opmPRMFTC";
  gint ii;

  wlan_hdr *volatile whdr;
  static wlan_hdr whdrs[4];
  gboolean retransmitted;

  whdr= &whdrs[0];

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "802.11");
  col_clear(pinfo->cinfo, COL_INFO);

  fcf = FETCH_FCF(0);
  frame_type_subtype = COMPOSE_FRAME_TYPE(fcf);
  if (frame_type_subtype == CTRL_CONTROL_WRAPPER)
    ctrl_fcf = FETCH_FCF(10);
  else
    ctrl_fcf = 0;

  if (fixed_length_header)
    hdr_len = DATA_LONG_HDR_LEN;
  else
    hdr_len = find_header_length (fcf, ctrl_fcf, is_ht);
  ohdr_len = hdr_len;
  if (datapad)
    hdr_len = roundup2(hdr_len, 4);

  fts_str = val_to_str_const(frame_type_subtype, frame_type_subtype_vals,
              "Unrecognized (Reserved frame)");
  col_set_str (pinfo->cinfo, COL_INFO, fts_str);


  flags = FCF_FLAGS (fcf);
  more_frags = HAVE_FRAGMENTS (flags);

  for (ii = 0; ii < 8; ii++) {
    if (! (flags & 0x80 >> ii)) {
      flag_str[ii] = '.';
    }
  }

  if (is_ht && IS_STRICTLY_ORDERED(flags) &&
    ((FCF_FRAME_TYPE(fcf) == MGT_FRAME) || (FCF_FRAME_TYPE(fcf) == DATA_FRAME &&
      DATA_FRAME_IS_QOS(frame_type_subtype)))) {
    htc_len = 4;
  }

  /* Add the FC to the current tree */
  if (tree)
    {
      ti = proto_tree_add_protocol_format (tree, proto_wlan, tvb, 0, hdr_len,
          "IEEE 802.11 %s", fts_str);
      hdr_tree = proto_item_add_subtree (ti, ett_80211);

      dissect_frame_control(hdr_tree, tvb, wlan_broken_fc, 0);

      if (frame_type_subtype == CTRL_PS_POLL)
        proto_tree_add_uint(hdr_tree, hf_ieee80211_assoc_id, tvb, 2, 2, TRUE);

      else
        proto_tree_add_uint (hdr_tree, hf_ieee80211_did_duration, tvb, 2, 2,
            tvb_get_letohs (tvb, 2));
    }

  /*
   * Decode the part of the frame header that isn't the same for all
   * frame types.
   */
  seq_control = 0;
  frag_number = 0;
  seq_number = 0;

  switch (FCF_FRAME_TYPE (fcf))
  {

    case MGT_FRAME:
      /*
       * All management frame types have the same header.
       */
      src = tvb_get_ptr (tvb, 10, 6);
      dst = tvb_get_ptr (tvb, 4, 6);

      SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst);
      SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst);

      /* for tap */
      SET_ADDRESS(&whdr->bssid, AT_ETHER, 6, tvb_get_ptr(tvb, 16,6));
      SET_ADDRESS(&whdr->src, AT_ETHER, 6, src);
      SET_ADDRESS(&whdr->dst, AT_ETHER, 6, dst);
      whdr->type = frame_type_subtype;

      seq_control = tvb_get_letohs(tvb, 22);
      frag_number = SEQCTL_FRAGMENT_NUMBER(seq_control);
      seq_number = SEQCTL_SEQUENCE_NUMBER(seq_control);

      col_append_fstr(pinfo->cinfo, COL_INFO,
            ", SN=%d", seq_number);

      col_append_fstr(pinfo->cinfo, COL_INFO,
            ", FN=%d",frag_number);

      if (tree)
      {
        proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_da, tvb, 4, 6, dst);

        proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_sa, tvb, 10, 6, src);

        /* add items for wlan.addr filter */
        hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 4, 6, dst);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 10, 6, src);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        proto_tree_add_item (hdr_tree, hf_ieee80211_addr_bssid, tvb, 16, 6, ENC_NA);

        proto_tree_add_uint (hdr_tree, hf_ieee80211_frag_number, tvb, 22, 2,
            frag_number);

        proto_tree_add_uint (hdr_tree, hf_ieee80211_seq_number, tvb, 22, 2,
            seq_number);
      }
      break;

    case CONTROL_FRAME:
    {
      /*
       * Control Wrapper frames insert themselves between address 1
       * and address 2 in a normal control frame.  Process address 1
       * first, then handle the rest of the frame in dissect_control.
       */
      if (frame_type_subtype == CTRL_CONTROL_WRAPPER) {
        offset = 10; /* FC + D/ID + Address 1 + CFC + HTC */
        ctrl_fcf = FETCH_FCF(10);
        ctrl_type_subtype = COMPOSE_FRAME_TYPE(ctrl_fcf);
      } else {
        offset = 10; /* FC + D/ID + Address 1 */
        ctrl_fcf = fcf;
        ctrl_type_subtype = frame_type_subtype;
      }

      switch (ctrl_type_subtype)
      {
        case CTRL_PS_POLL:
          addr1_str = "BSSID";
          addr1_hf = hf_ieee80211_addr_bssid;
          break;
        case CTRL_RTS:
        case CTRL_CTS:
        case CTRL_ACKNOWLEDGEMENT:
        case CTRL_CFP_END:
        case CTRL_CFP_ENDACK:
        case CTRL_BLOCK_ACK_REQ:
        case CTRL_BLOCK_ACK:
          addr1_str = "RA";
          addr1_hf = hf_ieee80211_addr_ra;
          break;
        default:
          break;
      }

      if (!addr1_str) /* XXX - Should we throw some sort of error? */
        break;

      /* Add address 1 */
      dst = tvb_get_ptr(tvb, 4, 6);
      set_dst_addr_cols(pinfo, dst, addr1_str);
      if (tree) {
        proto_tree_add_item(hdr_tree, addr1_hf, tvb, 4, 6, FALSE);
      }

      /*
       * Start shoving in other fields if needed.
       * XXX - Should we look for is_ht as well?
       */
      if (frame_type_subtype == CTRL_CONTROL_WRAPPER && tree) {
        cw_item = proto_tree_add_text(hdr_tree, tvb, offset, 2,
          "Contained Frame Control");
        cw_tree = proto_item_add_subtree (cw_item, ett_cntrl_wrapper_fc);
        dissect_frame_control(cw_tree, tvb, FALSE, offset);
        dissect_ht_control(hdr_tree, tvb, offset + 2);
        offset+=6;
        cw_item = proto_tree_add_text(hdr_tree, tvb, offset, 2,
          "Carried Frame");
        hdr_tree = proto_item_add_subtree (cw_item, ett_cntrl_wrapper_fc);
      }

      switch (ctrl_type_subtype)
      {
        case CTRL_PS_POLL:
        case CTRL_CFP_END:
        case CTRL_CFP_ENDACK:
        {
          src = tvb_get_ptr (tvb, offset, 6);
          set_src_addr_cols(pinfo, src, "BSSID");
          if (tree) {
            proto_tree_add_item(hdr_tree, hf_ieee80211_addr_ta, tvb, offset, 6, FALSE);
          }
          break;
        }

        case CTRL_RTS:
        {
          src = tvb_get_ptr (tvb, offset, 6);
          set_src_addr_cols(pinfo, src, "TA");
          if (tree) {
            proto_tree_add_item(hdr_tree, hf_ieee80211_addr_ta, tvb, offset, 6, FALSE);
          }
          break;
        }

        case CTRL_CONTROL_WRAPPER:
        {
          /* XXX - We shouldn't see this.  Should we throw an error? */
          break;
        }

        case CTRL_BLOCK_ACK_REQ:
        {
          src = tvb_get_ptr (tvb, offset, 6);
          set_src_addr_cols(pinfo, src, "TA");

          if (tree)
          {
            guint16 bar_control;
            guint8 block_ack_type;
            proto_item *bar_parent_item;
            proto_tree *bar_sub_tree;

            proto_tree_add_item(hdr_tree, hf_ieee80211_addr_ta, tvb, offset, 6, FALSE);
            offset += 6;

            bar_control = tvb_get_letohs(tvb, offset);
            block_ack_type = (bar_control & 0x0006) >> 1;
            proto_tree_add_uint(hdr_tree, hf_ieee80211_block_ack_request_type, tvb,
              offset, 1, block_ack_type);
            bar_parent_item = proto_tree_add_uint_format(hdr_tree,
              hf_ieee80211_block_ack_request_control, tvb, offset, 2, bar_control,
              "Block Ack Request (BAR) Control: 0x%04X", bar_control);
            bar_sub_tree = proto_item_add_subtree(bar_parent_item,
              ett_block_ack);
            proto_tree_add_boolean(bar_sub_tree,
              hf_ieee80211_block_ack_control_ack_policy, tvb, offset, 1, bar_control);
            proto_tree_add_boolean(bar_sub_tree, hf_ieee80211_block_ack_control_multi_tid,
              tvb, offset, 1, bar_control);
            proto_tree_add_boolean(bar_sub_tree,
              hf_ieee80211_block_ack_control_compressed_bitmap, tvb, offset, 1,
              bar_control);
            proto_tree_add_uint(bar_sub_tree, hf_ieee80211_block_ack_control_reserved,
              tvb, offset, 2, bar_control);

            switch (block_ack_type)
            {
              case 0: /*Basic BlockAckReq */
              {
                proto_tree_add_uint(bar_sub_tree,
                hf_ieee80211_block_ack_control_basic_tid_info, tvb, offset+1, 1,
                  bar_control);
                offset += 2;

                offset += add_fixed_field(hdr_tree, tvb, offset,
                  FIELD_BLOCK_ACK_SSC);
                break;
              }
              case 2: /* Compressed BlockAckReq */
              {
                proto_tree_add_uint(bar_sub_tree,
                hf_ieee80211_block_ack_control_compressed_tid_info, tvb, offset+1, 1,
                  bar_control);
                offset += 2;

                offset += add_fixed_field(hdr_tree, tvb, offset,
                  FIELD_BLOCK_ACK_SSC);
                break;
              }
              case 3: /* Multi-TID BlockAckReq */
              {
                guint8 tid_count, i;
                proto_tree *bar_mtid_tree, *bar_mtid_sub_tree;

                tid_count = ((bar_control & 0xF000) >> 12) + 1;
                proto_tree_add_uint_format(bar_sub_tree, hf_ieee80211_block_ack_control_multi_tid_info, tvb, offset+1, 1, bar_control,
                decode_numeric_bitfield(bar_control, 0xF000, 16,"Number of TIDs Present: 0x%%X"), tid_count);
                offset += 2;

                bar_parent_item = proto_tree_add_text (hdr_tree, tvb, offset, tid_count*4, "Per TID Info");
                bar_mtid_tree = proto_item_add_subtree(bar_parent_item, ett_block_ack);
                for (i = 1; i <= tid_count; i++) {
                  bar_parent_item = proto_tree_add_uint(bar_mtid_tree, hf_ieee80211_block_ack_multi_tid_info, tvb, offset, 4, i);
                  bar_mtid_sub_tree = proto_item_add_subtree(bar_parent_item, ett_block_ack);

                  bar_control = tvb_get_letohs(tvb, offset);
                  proto_tree_add_uint(bar_mtid_sub_tree, hf_ieee80211_block_ack_multi_tid_reserved, tvb, offset, 2, bar_control);
                  proto_tree_add_uint(bar_mtid_sub_tree, hf_ieee80211_block_ack_multi_tid_value, tvb, offset+1, 1, bar_control);
                  offset += 2;

                  offset += add_fixed_field(bar_mtid_sub_tree, tvb, offset, FIELD_BLOCK_ACK_SSC);
                }
                break;
              }
            }
          }
          break;
        }

        case CTRL_BLOCK_ACK:
        {
          src = tvb_get_ptr (tvb, offset, 6);
          set_src_addr_cols(pinfo, src, "TA");

          if (tree)
          {
            guint16 ba_control;
            guint8 block_ack_type;
            proto_item *ba_parent_item;
            proto_tree *ba_sub_tree;

            proto_tree_add_item(hdr_tree, hf_ieee80211_addr_ta, tvb, offset, 6, FALSE);
            offset += 6;

            ba_control = tvb_get_letohs(tvb, offset);
            block_ack_type = (ba_control & 0x0006) >> 1;
            proto_tree_add_uint(hdr_tree, hf_ieee80211_block_ack_type, tvb, offset, 1, block_ack_type);
            ba_parent_item = proto_tree_add_uint_format(hdr_tree,
              hf_ieee80211_block_ack_control, tvb, offset, 2, ba_control,
              "Block Ack (BA) Control: 0x%04X", ba_control);
            ba_sub_tree = proto_item_add_subtree(ba_parent_item, ett_block_ack);
            proto_tree_add_boolean(ba_sub_tree, hf_ieee80211_block_ack_control_ack_policy,
              tvb, offset, 1, ba_control);
            proto_tree_add_boolean(ba_sub_tree, hf_ieee80211_block_ack_control_multi_tid,
              tvb, offset, 1, ba_control);
            proto_tree_add_boolean(ba_sub_tree,
              hf_ieee80211_block_ack_control_compressed_bitmap, tvb, offset, 1,
              ba_control);
            proto_tree_add_uint(ba_sub_tree, hf_ieee80211_block_ack_control_reserved, tvb,
              offset, 2, ba_control);

            switch (block_ack_type)
            {
              case 0: /*Basic BlockAck */
              {
                proto_tree_add_uint(ba_sub_tree,
                hf_ieee80211_block_ack_control_basic_tid_info, tvb, offset+1, 1,
                  ba_control);
                offset += 2;

                offset += add_fixed_field(hdr_tree, tvb, offset, FIELD_BLOCK_ACK_SSC);
                proto_tree_add_item(hdr_tree, hf_ieee80211_block_ack_bitmap, tvb, offset, 128, FALSE);
                offset += 128;
                break;
              }
              case 2: /* Compressed BlockAck */
              {
                proto_tree_add_uint(ba_sub_tree, hf_ieee80211_block_ack_control_basic_tid_info, tvb, offset+1, 1, ba_control);
                offset += 2;

                offset += add_fixed_field(hdr_tree, tvb, offset, FIELD_BLOCK_ACK_SSC);
                proto_tree_add_item(hdr_tree, hf_ieee80211_block_ack_bitmap, tvb, offset, 8, FALSE);
                offset += 8;
                break;
              }
              case 3:  /* Multi-TID BlockAck */
              {
                guint8 tid_count, i;
                proto_tree *ba_mtid_tree, *ba_mtid_sub_tree;

                tid_count = ((ba_control & 0xF000) >> 12) + 1;
                proto_tree_add_uint_format(ba_sub_tree,
                hf_ieee80211_block_ack_control_compressed_tid_info, tvb, offset+1, 1,
                  ba_control, decode_numeric_bitfield(ba_control, 0xF000,
                  16,"Number of TIDs Present: 0x%%X"), tid_count);
                offset += 2;

                ba_parent_item = proto_tree_add_text (hdr_tree, tvb, offset, tid_count*4, "Per TID Info");
                ba_mtid_tree = proto_item_add_subtree(ba_parent_item, ett_block_ack);
                for (i=1; i<=tid_count; i++) {
                  ba_parent_item = proto_tree_add_uint(ba_mtid_tree, hf_ieee80211_block_ack_multi_tid_info, tvb, offset, 4, i);
                  ba_mtid_sub_tree = proto_item_add_subtree(ba_parent_item, ett_block_ack);

                  ba_control = tvb_get_letohs(tvb, offset);
                  proto_tree_add_uint(ba_mtid_sub_tree, hf_ieee80211_block_ack_multi_tid_reserved, tvb, offset, 2, ba_control);
                  proto_tree_add_uint(ba_mtid_sub_tree, hf_ieee80211_block_ack_multi_tid_value, tvb, offset+1, 1, ba_control);
                  offset += 2;

                  offset += add_fixed_field(ba_mtid_sub_tree, tvb, offset, FIELD_BLOCK_ACK_SSC);
                  proto_tree_add_item(ba_mtid_sub_tree, hf_ieee80211_block_ack_bitmap, tvb, offset, 8, FALSE);
                  offset += 8;
                }
                break;
              }
            }
          }
          break;
        }
      }
      break;
    }

    case DATA_FRAME:
      addr_type = FCF_ADDR_SELECTOR (fcf);

      /* In order to show src/dst address we must always do the following */
      switch (addr_type)
      {

        case DATA_ADDR_T1:
          src = tvb_get_ptr (tvb, 10, 6);
          dst = tvb_get_ptr (tvb, 4, 6);
          bssid = tvb_get_ptr (tvb, 16, 6);
          break;

        case DATA_ADDR_T2:
          src = tvb_get_ptr (tvb, 16, 6);
          dst = tvb_get_ptr (tvb, 4, 6);
          bssid = tvb_get_ptr (tvb, 10, 6);
          break;

        case DATA_ADDR_T3:
          src = tvb_get_ptr (tvb, 10, 6);
          dst = tvb_get_ptr (tvb, 16, 6);
          bssid = tvb_get_ptr (tvb, 4, 6);
          break;

        case DATA_ADDR_T4:
          src = tvb_get_ptr (tvb, 24, 6);
          dst = tvb_get_ptr (tvb, 16, 6);
          bssid = tvb_get_ptr (tvb, 16, 6);
          break;
      }

      SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src);
      SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst);
      SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, dst);

      /* for tap */

      SET_ADDRESS(&whdr->bssid, AT_ETHER, 6, bssid);
      SET_ADDRESS(&whdr->src, AT_ETHER, 6, src);
      SET_ADDRESS(&whdr->dst, AT_ETHER, 6, dst);
      whdr->type = frame_type_subtype;

      seq_control = tvb_get_letohs(tvb, 22);
      frag_number = SEQCTL_FRAGMENT_NUMBER(seq_control);
      seq_number = SEQCTL_SEQUENCE_NUMBER(seq_control);

      col_append_fstr(pinfo->cinfo, COL_INFO,
            ", SN=%d, FN=%d", seq_number,frag_number);

      /* Now if we have a tree we start adding stuff */
      if (tree)
      {

        switch (addr_type)
        {

          case DATA_ADDR_T1:
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_da, tvb, 4, 6, dst);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_sa, tvb, 10, 6, src);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_bssid, tvb, 16, 6, bssid);
            proto_tree_add_uint (hdr_tree, hf_ieee80211_frag_number, tvb, 22, 2,
               frag_number);
            proto_tree_add_uint (hdr_tree, hf_ieee80211_seq_number, tvb, 22, 2,
               seq_number);

            /* add items for wlan.addr filter */
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 4, 6, dst);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 10, 6, src);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            break;

          case DATA_ADDR_T2:
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_da, tvb, 4, 6, dst);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_bssid, tvb, 10, 6, bssid);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_sa, tvb, 16, 6, src);
            proto_tree_add_uint (hdr_tree, hf_ieee80211_frag_number, tvb, 22, 2,
               frag_number);
            proto_tree_add_uint (hdr_tree, hf_ieee80211_seq_number, tvb, 22, 2,
               seq_number);

            /* add items for wlan.addr filter */
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 4, 6, dst);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 16, 6, src);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            break;

          case DATA_ADDR_T3:
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_bssid, tvb, 4, 6, bssid);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_sa, tvb, 10, 6, src);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_da, tvb, 16, 6, dst);

            proto_tree_add_uint (hdr_tree, hf_ieee80211_frag_number, tvb, 22, 2,
               frag_number);
            proto_tree_add_uint (hdr_tree, hf_ieee80211_seq_number, tvb, 22, 2,
               seq_number);

            /* add items for wlan.addr filter */
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 10, 6, src);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 16, 6, dst);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            break;

          case DATA_ADDR_T4:
            proto_tree_add_item (hdr_tree, hf_ieee80211_addr_ra, tvb, 4, 6, ENC_NA);
            proto_tree_add_item (hdr_tree, hf_ieee80211_addr_ta, tvb, 10, 6, ENC_NA);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_da, tvb, 16, 6, dst);
            proto_tree_add_uint (hdr_tree, hf_ieee80211_frag_number, tvb, 22, 2,
               frag_number);
            proto_tree_add_uint (hdr_tree, hf_ieee80211_seq_number, tvb, 22, 2,
               seq_number);
            proto_tree_add_ether (hdr_tree, hf_ieee80211_addr_sa, tvb, 24, 6, src);

            /* add items for wlan.addr filter */
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 16, 6, dst);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            hidden_item = proto_tree_add_ether (hdr_tree, hf_ieee80211_addr, tvb, 24, 6, src);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
            break;
        }

      }

#ifdef MESH_OVERRIDES
      if (tree &&
          (FCF_ADDR_SELECTOR(fcf) == DATA_ADDR_T4 ||
           FCF_ADDR_SELECTOR(fcf) == DATA_ADDR_T2))
      {
        proto_item *msh_fields;
        proto_tree *msh_tree;

        guint16 mshoff;
        guint8 mesh_flags;
        guint8 mesh_ttl;
        guint32 mesh_seq_number;
        guint8 mesh_hdr_len;

        mshoff = hdr_len;
        mesh_flags = tvb_get_guint8(tvb, mshoff + 0);
        /* heuristic method to determine if this is a mesh frame */
        if (mesh_flags & ~MESH_FLAGS_ADDRESS_EXTENSION) {
#if 0
          g_warning("Invalid mesh flags: %x.  Interpreting as WDS frame.\n",  mesh_flags);
#endif
          break;
        }
        mesh_hdr_len = find_mesh_header_length(tvb_get_ptr(tvb, mshoff, 1), 0, fcf);
        mesh_ttl = tvb_get_guint8(tvb, mshoff + 1);
        mesh_seq_number = 0xffffff & tvb_get_letohl(tvb, mshoff + 2);

        msh_fields = proto_tree_add_text(hdr_tree, tvb, mshoff, mesh_hdr_len, "Mesh Header");
        msh_tree = proto_item_add_subtree (msh_fields, ett_msh_parameters);

        proto_tree_add_boolean_format (msh_tree, hf_ieee80211_mesh_flags,
              tvb, mshoff, 1, mesh_flags, "Address Extension %x", mesh_flags & MESH_FLAGS_ADDRESS_EXTENSION);
        proto_tree_add_uint (msh_tree, hf_ieee80211_mesh_ttl, tvb, mshoff + 1, 1, mesh_ttl);
        proto_tree_add_uint (msh_tree, hf_ieee80211_mesh_seq, tvb, mshoff + 2, 4, mesh_seq_number);
        switch (mesh_hdr_len) {
          case 24:
            proto_tree_add_item(msh_tree, hf_ieee80211_mesh_ae3, tvb, mshoff + 18, 6, ENC_NA);
          case 18:
            proto_tree_add_item(msh_tree, hf_ieee80211_mesh_ae2, tvb, mshoff + 12, 6, ENC_NA);
          case 12:
            proto_tree_add_item(msh_tree, hf_ieee80211_mesh_ae1, tvb, mshoff + 6, 6, ENC_NA);
          case 6:
            break;
          default:
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                "Invalid mesh header length (%d)\n",
                mesh_hdr_len);
        }
        hdr_len += mesh_hdr_len;
      }
#endif /* MESH_OVERRIDES */
      break;
  }

  len = tvb_length_remaining(tvb, hdr_len);
  reported_len = tvb_reported_length_remaining(tvb, hdr_len);

  switch (fcs_len)
    {
      case 0: /* Definitely has no FCS */
        has_fcs = FALSE;
        break;

      case 4: /* Definitely has an FCS */
        has_fcs = TRUE;
        break;

      case -2: /* Data frames have no FCS, other frames have an FCS */
        if (FCF_FRAME_TYPE (fcf) == DATA_FRAME)
          has_fcs = FALSE;
        else
          has_fcs = TRUE;
        break;

      default: /* Don't know - use "wlan_check_fcs" */
        has_fcs = wlan_check_fcs;
        break;
    }
  if (has_fcs)
    {
      /*
       * Well, this packet should, in theory, have an FCS.
       * Do we have the entire packet, and does it have enough data for
       * the FCS?
       */
      if (reported_len < 4)
      {
        /*
         * The packet is claimed not to even have enough data for a 4-byte
         * FCS.
         * Pretend it doesn't have an FCS.
         */
        ;
      }
      else if (len < reported_len)
      {
        /*
         * The packet is claimed to have enough data for a 4-byte FCS, but
         * we didn't capture all of the packet.
         * Slice off the 4-byte FCS from the reported length, and trim the
         * captured length so it's no more than the reported length; that
         * will slice off what of the FCS, if any, is in the captured
         * length.
         */
        reported_len -= 4;
        if (len > reported_len)
            len = reported_len;
      }
      else
      {
        /*
         * We have the entire packet, and it includes a 4-byte FCS.
         * Slice it off, and put it into the tree.
         */
        len -= 4;
        reported_len -= 4;
        if (tree)
        {
          guint32 sent_fcs = tvb_get_ntohl(tvb, hdr_len + len);
          guint32 fcs;

          if (datapad)
            fcs = crc32_802_tvb_padded(tvb, ohdr_len, hdr_len, len);
          else
            fcs = crc32_802_tvb(tvb, hdr_len + len);
          if (fcs == sent_fcs) {
            fcs_good = TRUE;
            fcs_bad = FALSE;
          } else {
            fcs_good = FALSE;
            fcs_bad = TRUE;
          }

          if(fcs_good) {
            fcs_item = proto_tree_add_uint_format(hdr_tree, hf_ieee80211_fcs, tvb,
                hdr_len + len, 4, sent_fcs,
                "Frame check sequence: 0x%08x [correct]", sent_fcs);
          } else {
            fcs_item = proto_tree_add_uint_format(hdr_tree, hf_ieee80211_fcs, tvb,
                hdr_len + len, 4, sent_fcs,
                "Frame check sequence: 0x%08x [incorrect, should be 0x%08x]",
                sent_fcs, fcs);
            flag_str[8] = '.';
          }

          proto_tree_set_appendix(hdr_tree, tvb, hdr_len + len, 4);

          fcs_tree = proto_item_add_subtree(fcs_item, ett_fcs);

          fcs_item = proto_tree_add_boolean(fcs_tree,
              hf_ieee80211_fcs_good, tvb,
              hdr_len + len, 4,
              fcs_good);
          PROTO_ITEM_SET_GENERATED(fcs_item);

          fcs_item = proto_tree_add_boolean(fcs_tree,
              hf_ieee80211_fcs_bad, tvb,
              hdr_len + len, 4,
              fcs_bad);
          PROTO_ITEM_SET_GENERATED(fcs_item);
        }
      }
    } else {
      flag_str[8] = '\0';
    }

    proto_item_append_text(ti, ", Flags: %s", flag_str);
    col_append_fstr (pinfo->cinfo, COL_INFO, ", Flags=%s", flag_str);


  /*
   * Only management and data frames have a body, so we don't have
   * anything more to do for other types of frames.
   */
  switch (FCF_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      if (htc_len == 4) {
        dissect_ht_control(hdr_tree, tvb, ohdr_len - 4);
      }
      break;

    case DATA_FRAME:
      if (tree && DATA_FRAME_IS_QOS(frame_type_subtype))
      {
        proto_item *qos_fields;
        proto_tree *qos_tree;

        guint16 qosoff;
        guint16 qos_control;
        guint16 qos_tid;
        guint16 qos_priority;
        guint16 qos_ack_policy;
        guint16 qos_amsdu_present;
        guint16 qos_eosp;
        guint16 qos_field_content;

        /*
         * We calculate the offset to the QoS header data as
         * an offset relative to the end of the header.  But
         * when the header has been padded to align the data
         * this must be done relative to true header size, not
         * the padded/aligned value.  To simplify this work we
         * stash the original header size in ohdr_len instead
         * of recalculating it.
         */
        qosoff = ohdr_len - htc_len - 2;
        qos_fields = proto_tree_add_text(hdr_tree, tvb, qosoff, 2,
            "QoS Control");
        qos_tree = proto_item_add_subtree (qos_fields, ett_qos_parameters);

        qos_control = tvb_get_letohs(tvb, qosoff + 0);
        qos_tid = QOS_TID(qos_control);
        qos_priority = QOS_PRIORITY(qos_control);
        qos_ack_policy = QOS_ACK_POLICY(qos_control);
        qos_amsdu_present = QOS_AMSDU_PRESENT(qos_control);
        qos_eosp = QOS_EOSP(qos_control);
        qos_field_content = QOS_FIELD_CONTENT(qos_control);

        proto_tree_add_uint (qos_tree, hf_ieee80211_qos_tid, tvb,
            qosoff, 1, qos_tid);

        proto_tree_add_uint_format (qos_tree, hf_ieee80211_qos_priority, tvb,
            qosoff, 1, qos_priority,
            "Priority: %d (%s) (%s)",
            qos_priority, qos_tags[qos_priority], qos_acs[qos_priority]);

        if (flags & FLAG_FROM_DS) {
          proto_tree_add_boolean (qos_tree, hf_ieee80211_qos_eosp, tvb,
              qosoff, 1, qos_control);
        } else {
          proto_tree_add_boolean (qos_tree, hf_ieee80211_qos_bit4, tvb,
              qosoff, 1, qos_control);
        }

        proto_tree_add_uint (qos_tree, hf_ieee80211_qos_ack_policy, tvb, qosoff, 1,
            qos_ack_policy);

        if (flags & FLAG_FROM_DS) {
          if (!DATA_FRAME_IS_NULL(frame_type_subtype)) {
            proto_tree_add_boolean(qos_tree, hf_ieee80211_qos_amsdu_present, tvb,
                qosoff, 1, qos_amsdu_present);
            is_amsdu = qos_amsdu_present;
          }
          if (DATA_FRAME_IS_CF_POLL(frame_type_subtype)) {
            /* txop limit */
            if (qos_field_content == 0) {
              proto_tree_add_uint_format_value (qos_tree, hf_ieee80211_qos_txop_limit, tvb,
                  qosoff + 1, 1, qos_field_content,
                                                "transmit one frame immediately (0)");
            } else {
              proto_tree_add_uint (qos_tree, hf_ieee80211_qos_txop_limit, tvb,
                                   qosoff + 1, 1, qos_field_content);
            }
          } else {
            /* qap ps buffer state */
            proto_item *qos_ps_buf_state_fields;
            proto_tree *qos_ps_buf_state_tree;
            guint8 qap_buf_load;

            qos_ps_buf_state_fields = proto_tree_add_text(qos_tree, tvb, qosoff + 1, 1,
                "QAP PS Buffer State: 0x%x", qos_field_content);
            qos_ps_buf_state_tree = proto_item_add_subtree (qos_ps_buf_state_fields, ett_qos_ps_buf_state);

            proto_tree_add_boolean (qos_ps_buf_state_tree, hf_ieee80211_qos_buf_state_indicated,
                                    tvb, qosoff + 1, 1, qos_field_content);

            if (QOS_PS_BUF_STATE_INDICATED(qos_field_content)) {
              proto_tree_add_uint (qos_ps_buf_state_tree, hf_ieee80211_qos_highest_pri_buf_ac, tvb,
                  qosoff + 1, 1, qos_field_content);

              qap_buf_load = QOS_PS_QAP_BUF_LOAD(qos_field_content);
              switch (qap_buf_load) {

              case 0:
                proto_tree_add_uint_format_value (qos_ps_buf_state_tree, hf_ieee80211_qos_qap_buf_load, tvb,
                    qosoff + 1, 1, qos_field_content,
                    "no buffered traffic (0)");
                break;

              default:
                proto_tree_add_uint_format_value (qos_ps_buf_state_tree, hf_ieee80211_qos_qap_buf_load, tvb,
                    qosoff + 1, 1, qos_field_content,
                    "%d octets (%d)", qap_buf_load*4096, qap_buf_load);
                break;

              case 15:
                proto_tree_add_uint_format_value (qos_ps_buf_state_tree, hf_ieee80211_qos_qap_buf_load, tvb,
                    qosoff + 1, 1, qos_field_content,
                    "greater than 57344 octets (15)");
                break;
              }
            }
          }
        } else {
          if (!DATA_FRAME_IS_NULL(frame_type_subtype)) {
            proto_tree_add_boolean(qos_tree, hf_ieee80211_qos_amsdu_present, tvb,
                qosoff, 1, qos_amsdu_present);
            is_amsdu = qos_amsdu_present;
          }
          if (qos_eosp) {
            /* queue size */
            switch (qos_field_content) {

            case 0:
              proto_tree_add_uint_format_value (qos_tree, hf_ieee80211_qos_queue_size,
                                                tvb, qosoff + 1, 1, qos_field_content,
                  "no buffered traffic in the queue (0)");
              break;

            default:
              proto_tree_add_uint_format_value (qos_tree, hf_ieee80211_qos_queue_size,
                                                tvb, qosoff + 1, 1, qos_field_content,
                                                "%u bytes (%u)", qos_field_content*256, qos_field_content);
              break;

            case 254:
              proto_tree_add_uint_format_value (qos_tree, hf_ieee80211_qos_queue_size,
                                                tvb, qosoff + 1, 1, qos_field_content,
                  "more than 64768 octets (254)");
              break;

            case 255:
              proto_tree_add_uint_format_value (qos_tree, hf_ieee80211_qos_queue_size,
                                                tvb, qosoff + 1, 1, qos_field_content,
                  "unspecified or unknown (256)");
              break;
            }
          } else {
            /* txop duration requested */
            if (qos_field_content == 0) {
              proto_tree_add_uint_format_value (qos_tree, hf_ieee80211_qos_txop_dur_req,
                                                tvb, qosoff + 1, 1, qos_field_content,
                                                "no TXOP requested (0)");
            } else {
              proto_tree_add_uint (qos_tree, hf_ieee80211_qos_txop_dur_req,
                                   tvb, qosoff + 1, 1, qos_field_content);
            }
          }
        }

        /* Do we have +HTC? */
        if (htc_len == 4) {
          dissect_ht_control(hdr_tree, tvb, ohdr_len - 4);
        }
      } /* end of qos control field */

#ifdef HAVE_AIRPDCAP
      /* Davide Schiera (2006-11-21): process handshake packet with AirPDcap    */
      /* the processing will take care of 4-way handshake sessions for WPA    */
      /* and WPA2 decryption                                  */
      if (enable_decryption && !pinfo->fd->flags.visited) {
        const guint8 *enc_data = tvb_get_ptr(tvb, 0, hdr_len+reported_len);
        AirPDcapPacketProcess(&airpdcap_ctx, enc_data, hdr_len, hdr_len+reported_len, NULL, 0, NULL, TRUE, FALSE);
      }
      /* Davide Schiera --------------------------------------------------------  */
#endif

      /*
       * No-data frames don't have a body.
       */
      if (DATA_FRAME_IS_NULL(frame_type_subtype))
        return;

      if (!wlan_subdissector) {
        guint fnum = 0;

        /* key: bssid:src
         * data: last seq_control seen and frame number
         */
        retransmitted = FALSE;
        if(!pinfo->fd->flags.visited){
          retransmit_key key;
          retransmit_key *result;

          memcpy(key.bssid, bssid, 6);
          memcpy(key.src, src, 6);
          key.seq_control = 0;
          result = (retransmit_key *)g_hash_table_lookup(fc_analyse_retransmit_table, &key);
          if (result && result->seq_control == seq_control) {
               /* keep a pointer to the first seen frame, could be done with proto data? */
               fnum = result->fnum;
               g_hash_table_insert(fc_first_frame_table, GINT_TO_POINTER( pinfo->fd->num),
                  GINT_TO_POINTER(fnum));
               retransmitted = TRUE;
          } else {
               /* first time or new seq*/
               if (!result) {
                  result = se_alloc(sizeof(retransmit_key));
                  *result = key;
                  g_hash_table_insert(fc_analyse_retransmit_table, result, result);
               }
               result->seq_control = seq_control;
               result->fnum =  pinfo->fd->num;
           }
        }
        else if ((fnum = GPOINTER_TO_UINT(g_hash_table_lookup(fc_first_frame_table, GINT_TO_POINTER( pinfo->fd->num))))) {
           retransmitted = TRUE;
        }

        if (retransmitted) {
            col_append_str(pinfo->cinfo, COL_INFO, " [retransmitted]");
            if (tree) {
                proto_item *item;

                item=proto_tree_add_none_format(hdr_tree, hf_ieee80211_fc_analysis_retransmission, tvb, 0, 0, "Retransmitted frame");
                PROTO_ITEM_SET_GENERATED(item);
                item=proto_tree_add_uint(hdr_tree, hf_ieee80211_fc_analysis_retransmission_frame,tvb, 0, 0, fnum);
                PROTO_ITEM_SET_GENERATED(item);
            }
            next_tvb = tvb_new_subset (tvb, hdr_len, len, reported_len);
            call_dissector(data_handle, next_tvb, pinfo, tree);
            goto end_of_wlan;
        }
      }

      break;

    case CONTROL_FRAME:
      return;

    default:
      return;
    }

  if (IS_PROTECTED(FCF_FLAGS(fcf)) && wlan_ignore_wep != WLAN_IGNORE_WEP_WO_IV) {
    /*
     * It's a WEP or WPA encrypted frame; dissect the protections parameters
     * and decrypt the data, if we have a matching key. Otherwise display it as data.
     */

    gboolean can_decrypt = FALSE;
    proto_tree *wep_tree = NULL;
    guint32 iv;
    guint8 key, keybyte;

    /* Davide Schiera (2006-11-27): define algorithms constants and macros  */
#ifdef HAVE_AIRPDCAP
#define PROTECTION_ALG_TKIP  AIRPDCAP_KEY_TYPE_TKIP
#define PROTECTION_ALG_CCMP  AIRPDCAP_KEY_TYPE_CCMP
#define PROTECTION_ALG_WEP  AIRPDCAP_KEY_TYPE_WEP
#define PROTECTION_ALG_RSNA  PROTECTION_ALG_CCMP | PROTECTION_ALG_TKIP
#else
#define PROTECTION_ALG_WEP  0
#define PROTECTION_ALG_TKIP  1
#define PROTECTION_ALG_CCMP  2
#define PROTECTION_ALG_RSNA  PROTECTION_ALG_CCMP | PROTECTION_ALG_TKIP
#endif
    guint8 algorithm=G_MAXUINT8;
    /* Davide Schiera (2006-11-27): added macros to check the algorithm    */
    /* used could be TKIP or CCMP                            */
#define IS_TKIP(tvb, hdr_len)  (tvb_get_guint8(tvb, hdr_len + 1) & 0x20)
#define IS_CCMP(tvb, hdr_len)  (tvb_get_guint8(tvb, hdr_len + 2) == 0)
    /* Davide Schiera -----------------------------------------------------  */

#ifdef  HAVE_AIRPDCAP
    /* Davide Schiera (2006-11-21): recorded original lengths to pass them  */
    /* to the packets process function                        */
    guint32 sec_header=0;
    guint32 sec_trailer=0;

    next_tvb = try_decrypt(tvb, hdr_len, reported_len, &algorithm, &sec_header, &sec_trailer);
#endif
    /* Davide Schiera -----------------------------------------------------  */

    keybyte = tvb_get_guint8(tvb, hdr_len + 3);
    key = KEY_OCTET_WEP_KEY(keybyte);
    if ((keybyte & KEY_EXTIV) && (len >= EXTIV_LEN)) {
      /* Extended IV; this frame is likely encrypted with TKIP or CCMP */


      if (tree) {
        proto_item *extiv_fields;

#ifdef HAVE_AIRPDCAP
        /* Davide Schiera (2006-11-27): differentiated CCMP and TKIP if  */
        /* it's possible                                */
        if (algorithm==PROTECTION_ALG_TKIP)
          extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
              "TKIP parameters");
        else if (algorithm==PROTECTION_ALG_CCMP)
          extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
            "CCMP parameters");
        else {
          /* Davide Schiera --------------------------------------------  */
#endif
          /* Davide Schiera (2006-11-27): differentiated CCMP and TKIP if*/
          /* it's possible                              */
          if (IS_TKIP(tvb, hdr_len)) {
            algorithm=PROTECTION_ALG_TKIP;
            extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
                "TKIP parameters");
          } else if (IS_CCMP(tvb, hdr_len)) {
            algorithm=PROTECTION_ALG_CCMP;
            extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
                "CCMP parameters");
          } else
            extiv_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 8,
                "TKIP/CCMP parameters");
#ifdef HAVE_AIRPDCAP
        }
#endif
        proto_item_set_len (ti, hdr_len + 8);

        wep_tree = proto_item_add_subtree (extiv_fields, ett_wep_parameters);

        if (algorithm==PROTECTION_ALG_TKIP) {
          g_snprintf(out_buff, SHORT_STR, "0x%08X%02X%02X",
              tvb_get_letohl(tvb, hdr_len + 4),
              tvb_get_guint8(tvb, hdr_len),
              tvb_get_guint8(tvb, hdr_len + 2));
          proto_tree_add_string(wep_tree, hf_ieee80211_tkip_extiv, tvb, hdr_len,
              EXTIV_LEN, out_buff);
        } else if (algorithm==PROTECTION_ALG_CCMP) {
          g_snprintf(out_buff, SHORT_STR, "0x%08X%02X%02X",
              tvb_get_letohl(tvb, hdr_len + 4),
              tvb_get_guint8(tvb, hdr_len + 1),
              tvb_get_guint8(tvb, hdr_len));
          proto_tree_add_string(wep_tree, hf_ieee80211_ccmp_extiv, tvb, hdr_len,
              EXTIV_LEN, out_buff);
        }

        proto_tree_add_uint(wep_tree, hf_ieee80211_wep_key, tvb, hdr_len + 3, 1, key);
      }

      /* Subtract out the length of the IV. */
      len -= EXTIV_LEN;
      reported_len -= EXTIV_LEN;
      ivlen = EXTIV_LEN;
      /* It is unknown whether this is TKIP or CCMP, so let's not even try to
       * parse TKIP Michael MIC+ICV or CCMP MIC. */

#ifdef HAVE_AIRPDCAP
      /* Davide Schiera (2006-11-21): enable TKIP and CCMP decryption      */
      /* checking for the trailer                            */
      if (next_tvb!=NULL) {
        if (reported_len < (gint) sec_trailer) {
          /* There is no space for a trailer, ignore it and don't decrypt  */
          ;
        } else if (len < reported_len) {
          /* There is space for a trailer, but we haven't capture all the  */
          /* packet. Slice off the trailer, but don't try to decrypt      */
          reported_len -= sec_trailer;
          if (len > reported_len)
            len = reported_len;
        } else {
          /* Ok, we have a trailer and the whole packet. Decrypt it!      */
          /* TODO: At the moment we won't add the trailer to the tree,    */
          /* so don't remove the trailer from the packet              */
          len -= sec_trailer;
          reported_len -= sec_trailer;
          can_decrypt = TRUE;
        }
      }
      /* Davide Schiera --------------------------------------------------  */
#endif
    } else {
      /* No Ext. IV - WEP packet */
      /*
       * XXX - pass the IV and key to "try_decrypt_wep()", and have it pass
       * them to "wep_decrypt()", rather than having "wep_decrypt()" extract
       * them itself.
       *
       * Also, just pass the data *following* the WEP parameters as the
       * buffer to decrypt.
       */
      iv = tvb_get_ntoh24(tvb, hdr_len);
      if (tree) {
        proto_item *wep_fields;

        wep_fields = proto_tree_add_text(hdr_tree, tvb, hdr_len, 4,
            "WEP parameters");

        wep_tree = proto_item_add_subtree (wep_fields, ett_wep_parameters);
        proto_tree_add_uint (wep_tree, hf_ieee80211_wep_iv, tvb, hdr_len, 3, iv);
        tvb_memcpy(tvb, iv_buff, hdr_len, 3);
        is_iv_bad = weak_iv(iv_buff);
        if (is_iv_bad != -1) {
          proto_tree_add_boolean_format (wep_tree, hf_ieee80211_wep_iv_weak,
              tvb, 0, 0, TRUE,
              "Weak IV for key byte %d",
              is_iv_bad);
        }
      }
      if (tree)
        proto_tree_add_uint (wep_tree, hf_ieee80211_wep_key, tvb, hdr_len + 3, 1, key);

      /* Subtract out the length of the IV. */
      len -= 4;
      reported_len -= 4;
      ivlen = 4;

      /* Davide Schiera (2006-11-27): Even if the decryption was not */
      /* successful, set the algorithm                               */
      algorithm=PROTECTION_ALG_WEP;

      /*
       * Well, this packet should, in theory, have an ICV.
       * Do we have the entire packet, and does it have enough data for
       * the ICV?
       */
      if (reported_len < 4) {
        /*
         * The packet is claimed not to even have enough data for a
         * 4-byte ICV.
         * Pretend it doesn't have an ICV.
         */
        ;
      } else if (len < reported_len) {
        /*
         * The packet is claimed to have enough data for a 4-byte ICV,
         * but we didn't capture all of the packet.
         * Slice off the 4-byte ICV from the reported length, and trim
         * the captured length so it's no more than the reported length;
         * that will slice off what of the ICV, if any, is in the
         * captured length.
         */
        reported_len -= 4;
        if (len > reported_len)
          len = reported_len;
      } else {
        /*
         * We have the entire packet, and it includes a 4-byte ICV.
         * Slice it off, and put it into the tree.
         *
         * We only support decrypting if we have the the ICV.
         *
         * XXX - the ICV is encrypted; we're putting the encrypted
         * value, not the decrypted value, into the tree.
         */
        len -= 4;
        reported_len -= 4;
        can_decrypt = TRUE;
      }
    }

    if (algorithm == PROTECTION_ALG_WEP) {
      g_strlcpy (wlan_stats.protection, "WEP", MAX_PROTECT_LEN);
    } else if (algorithm == PROTECTION_ALG_TKIP) {
      g_strlcpy (wlan_stats.protection, "TKIP", MAX_PROTECT_LEN);
    } else if (algorithm == PROTECTION_ALG_CCMP) {
      g_strlcpy (wlan_stats.protection, "CCMP", MAX_PROTECT_LEN);
    } else {
      g_strlcpy (wlan_stats.protection, "Unknown", MAX_PROTECT_LEN);
    }

#ifndef HAVE_AIRPDCAP
    if (can_decrypt)
      next_tvb = try_decrypt_wep(tvb, hdr_len, reported_len + 8);
#else
    /* Davide Schiera (2006-11-26): decrypted before parsing header and    */
    /* protection header                                  */
#endif
    if (!can_decrypt || next_tvb == NULL) {
      /*
       * WEP decode impossible or failed, treat payload as raw data
       * and don't attempt fragment reassembly or further dissection.
       */
      next_tvb = tvb_new_subset(tvb, hdr_len + ivlen, len, reported_len);

      if (tree) {
        /* Davide Schiera (2006-11-21): added WEP or WPA separation      */
        if (algorithm==PROTECTION_ALG_WEP) {
          if (can_decrypt)
            proto_tree_add_uint_format (wep_tree, hf_ieee80211_wep_icv, tvb,
                hdr_len + ivlen + len, 4,
                tvb_get_ntohl(tvb, hdr_len + ivlen + len),
                "WEP ICV: 0x%08x (not verified)",
                tvb_get_ntohl(tvb, hdr_len + ivlen + len));
        } else if (algorithm==PROTECTION_ALG_CCMP) {
        } else if (algorithm==PROTECTION_ALG_TKIP) {
        }
      }
      /* Davide Schiera (2006-11-21) ----------------------------------  */

      if (pinfo->ethertype != ETHERTYPE_CENTRINO_PROMISC && wlan_ignore_wep == WLAN_IGNORE_WEP_NO) {
        /* Some wireless drivers (such as Centrino) WEP payload already decrypted */
        call_dissector(data_handle, next_tvb, pinfo, tree);
        goto end_of_wlan;
      }
    } else {
      /* Davide Schiera (2006-11-21): added WEP or WPA separation        */
      if (algorithm==PROTECTION_ALG_WEP) {
        if (tree)
          proto_tree_add_uint_format (wep_tree, hf_ieee80211_wep_icv, tvb,
              hdr_len + ivlen + len, 4,
              tvb_get_ntohl(tvb, hdr_len + ivlen + len),
              "WEP ICV: 0x%08x (correct)",
              tvb_get_ntohl(tvb, hdr_len + ivlen + len));

        add_new_data_source(pinfo, next_tvb, "Decrypted WEP data");
      } else if (algorithm==PROTECTION_ALG_CCMP) {
        add_new_data_source(pinfo, next_tvb, "Decrypted CCMP data");
      } else if (algorithm==PROTECTION_ALG_TKIP) {
        add_new_data_source(pinfo, next_tvb, "Decrypted TKIP data");
      }
      /* Davide Schiera (2006-11-21) -------------------------------------  */
      /* Davide Schiera (2006-11-27): undefine macros and definitions  */
#undef IS_TKIP
#undef IS_CCMP
#undef PROTECTION_ALG_CCMP
#undef PROTECTION_ALG_TKIP
#undef PROTECTION_ALG_WEP
      /* Davide Schiera --------------------------------------------------  */
    }

    /*
     * WEP decryption successful!
     *
     * Use the tvbuff we got back from the decryption; the data starts at
     * the beginning.  The lengths are already correct for the decoded WEP
     * payload.
     */
    hdr_len = 0;

  } else {
    /*
     * Not a WEP-encrypted frame; just use the data from the tvbuff
     * handed to us.
     *
     * The payload starts at "hdr_len" (i.e., just past the 802.11
     * MAC header), the length of data in the tvbuff following the
     * 802.11 header is "len", and the length of data in the packet
     * following the 802.11 header is "reported_len".
     */
    next_tvb = tvb;
  }

  /*
   * Do defragmentation if "wlan_defragment" is true, and we have more
   * fragments or this isn't the first fragment.
   *
   * We have to do some special handling to catch frames that
   * have the "More Fragments" indicator not set but that
   * don't show up as reassembled and don't have any other
   * fragments present.  Some networking interfaces appear
   * to do reassembly even when you're capturing raw packets
   * *and* show the reassembled packet without the "More
   * Fragments" indicator set *but* with a non-zero fragment
   * number.
   *
   * "fragment_add_seq_802_11()" handles that; we want to call it
   * even if we have a short frame, so that it does those checks - if
   * the frame is short, it doesn't do reassembly on it.
   *
   * (This could get some false positives if we really *did* only
   * capture the last fragment of a fragmented packet, but that's
   * life.)
   */
  save_fragmented = pinfo->fragmented;
  if (wlan_defragment && (more_frags || frag_number != 0)) {
    fragment_data *fd_head;

    /*
     * If we've already seen this frame, look it up in the
     * table of reassembled packets, otherwise add it to
     * whatever reassembly is in progress, if any, and see
     * if it's done.
     */
    if (reported_len < 0)
      THROW(ReportedBoundsError);
    fd_head = fragment_add_seq_802_11(next_tvb, hdr_len, pinfo, seq_number,
        wlan_fragment_table,
        wlan_reassembled_table,
        frag_number,
        reported_len,
        more_frags);
    next_tvb = process_reassembled_data(tvb, hdr_len, pinfo,
        "Reassembled 802.11", fd_head,
        &frag_items, NULL, hdr_tree);
  } else {
    /*
     * If this is the first fragment, dissect its contents, otherwise
     * just show it as a fragment.
     */
    if (frag_number != 0) {
      /* Not the first fragment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First fragment, or not fragmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset (next_tvb, hdr_len, len, reported_len);

      /*
       * If this is the first fragment, but not the only fragment,
       * tell the next protocol that.
       */
      if (more_frags)
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as an incomplete fragment. */
    col_set_str(pinfo->cinfo, COL_INFO, "Fragmented IEEE 802.11 frame");
    next_tvb = tvb_new_subset (tvb, hdr_len, len, reported_len);
    call_dissector(data_handle, next_tvb, pinfo, tree);
    pinfo->fragmented = save_fragmented;
    goto end_of_wlan;
  }

  switch (FCF_FRAME_TYPE (fcf))
    {

    case MGT_FRAME:
      dissect_ieee80211_mgt (fcf, next_tvb, pinfo, tree);
      break;

    case DATA_FRAME:
      if (is_amsdu && tvb_reported_length_remaining(next_tvb, 0) > 4){
        tvbuff_t *volatile msdu_tvb = NULL;
        guint32 msdu_offset = 0;
        guint16 i = 1;
        const guint8 *lcl_src = NULL;
        const guint8 *lcl_dst = NULL;
        guint16 msdu_length;
        proto_item *parent_item;
        proto_tree *mpdu_tree;
        proto_tree *subframe_tree;

        parent_item = proto_tree_add_protocol_format(tree, proto_aggregate, next_tvb, 0,
                                    tvb_reported_length_remaining(next_tvb, 0), "IEEE 802.11 Aggregate MSDU");
        mpdu_tree = proto_item_add_subtree(parent_item, ett_msdu_aggregation_parent_tree);

        do {
          lcl_dst = tvb_get_ptr (next_tvb, msdu_offset, 6);
          lcl_src = tvb_get_ptr (next_tvb, msdu_offset+6, 6);
          msdu_length = tvb_get_ntohs (next_tvb, msdu_offset+12);

          parent_item = proto_tree_add_uint_format(mpdu_tree, hf_ieee80211_amsdu_msdu_header_text, next_tvb,
                            msdu_offset, roundup2(msdu_offset+14+msdu_length, 4),
                            i, "A-MSDU Subframe #%u", i);
          subframe_tree = proto_item_add_subtree(parent_item, ett_msdu_aggregation_subframe_tree);
          i++;

          proto_tree_add_ether(subframe_tree, hf_ieee80211_addr_da, next_tvb, msdu_offset, 6, lcl_dst);
          proto_tree_add_ether(subframe_tree, hf_ieee80211_addr_sa, next_tvb, msdu_offset+6, 6, lcl_src);
          proto_tree_add_uint_format(subframe_tree, hf_ieee80211_mcsset_highest_data_rate, next_tvb, msdu_offset+12, 2,
          msdu_length, "MSDU length: 0x%04X", msdu_length);

          msdu_offset += 14;
          msdu_tvb = tvb_new_subset(next_tvb, msdu_offset, msdu_length, -1);
          call_dissector(llc_handle, msdu_tvb, pinfo, subframe_tree);
          msdu_offset = roundup2(msdu_offset+msdu_length, 4);
        } while (tvb_reported_length_remaining(next_tvb, msdu_offset) > 14);

        break;
      }
      /* I guess some bridges take Netware Ethernet_802_3 frames,
         which are 802.3 frames (with a length field rather than
         a type field, but with no 802.2 header in the payload),
         and just stick the payload into an 802.11 frame.  I've seen
         captures that show frames of that sort.

         We also handle some odd form of encapsulation in which a
         complete Ethernet frame is encapsulated within an 802.11
         data frame, with no 802.2 header.  This has been seen
         from some hardware.

         On top of that, at least at some point it appeared that
         the OLPC XO sent out frames with two bytes of 0 between
         the "end" of the 802.11 header and the beginning of
         the payload.

         So, if the packet doesn't start with 0xaa 0xaa:

           we first use the same scheme that linux-wlan-ng does to detect
           those encapsulated Ethernet frames, namely looking to see whether
           the frame either starts with 6 octets that match the destination
           address from the 802.11 header or has 6 octets that match the
           source address from the 802.11 header following the first 6 octets,
           and, if so, treat it as an encapsulated Ethernet frame;

           otherwise, we use the same scheme that we use in the Ethernet
           dissector to recognize Netware 802.3 frames, namely checking
           whether the packet starts with 0xff 0xff and, if so, treat it
           as an encapsulated IPX frame, and then check whether the
           packet starts with 0x00 0x00 and, if so, treat it as an OLPC
           frame. */
      encap_type = ENCAP_802_2;
      TRY {
        octet1 = tvb_get_guint8(next_tvb, 0);
        octet2 = tvb_get_guint8(next_tvb, 1);
        if (octet1 != 0xaa || octet2 != 0xaa) {
          if (tvb_memeql(next_tvb, 6, pinfo->dl_src.data, 6) == 0 ||
              tvb_memeql(next_tvb, 0, pinfo->dl_dst.data, 6) == 0)
            encap_type = ENCAP_ETHERNET;
          else if (octet1 == 0xff && octet2 == 0xff)
            encap_type = ENCAP_IPX;
          else if (octet1 == 0x00 && octet2 == 0x00) {
            proto_tree_add_text(tree, next_tvb, 0, 2, "Mysterious OLPC stuff");
            next_tvb = tvb_new_subset_remaining (next_tvb, 2);
          }
        }
      }
      CATCH2(BoundsError, ReportedBoundsError) {
      ; /* do nothing */

      }
      ENDTRY;

      switch (encap_type) {

      case ENCAP_802_2:
        call_dissector(llc_handle, next_tvb, pinfo, tree);
        break;

      case ENCAP_ETHERNET:
        call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
        break;

      case ENCAP_IPX:
        call_dissector(ipx_handle, next_tvb, pinfo, tree);
        break;
      }
      break;
    }
  pinfo->fragmented = save_fragmented;

  end_of_wlan:
  whdr->stats = wlan_stats;
  tap_queue_packet(wlan_tap, pinfo, whdr);
  memset (&wlan_stats, 0, sizeof wlan_stats);
}
