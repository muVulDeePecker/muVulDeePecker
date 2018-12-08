static int
CVE_2012_1594_VULN_dissect_vendor_ie_wpawme(proto_tree * tree, tvbuff_t * tvb, int offset, guint32 tag_len, int ftype)
{
  guint8 type;

  proto_tree_add_item(tree, hf_ieee80211_wfa_ie_type, tvb, offset, 1, ENC_NA);
  type = tvb_get_guint8(tvb, offset);
  proto_item_append_text(tree, ": %s", val_to_str(type, ieee802111_wfa_ie_type_vals, "Unknown %d" ));
  offset += 1;

  switch(type){
    case 1:   /* Wi-Fi Protected Access (WPA) */
    {
      proto_item *wpa_mcs_item, *wpa_ucs_item, *wpa_akms_item;
      proto_item *wpa_sub_ucs_item, *wpa_sub_akms_item;
      proto_tree *wpa_mcs_tree, *wpa_ucs_tree, *wpa_akms_tree;
      proto_tree *wpa_sub_ucs_tree, *wpa_sub_akms_tree;
      guint16 i, ucs_count, akms_count;

      proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wpa_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;

      /* Multicast Cipher Suite */
      wpa_mcs_item = proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wpa_mcs, tvb, offset, 4, FALSE);
      wpa_mcs_tree = proto_item_add_subtree(wpa_mcs_item, ett_wpa_mcs_tree);
      proto_tree_add_item(wpa_mcs_tree, hf_ieee80211_wfa_ie_wpa_mcs_oui, tvb, offset, 3, FALSE);

      /* Check if OUI is 00:50:F2 (WFA) */
      if(tvb_get_ntoh24(tvb, offset) == 0x0050F2)
      {
        proto_tree_add_item(wpa_mcs_tree, hf_ieee80211_wfa_ie_wpa_mcs_wfa_type, tvb, offset + 3, 1, FALSE);
      } else {
        proto_tree_add_item(wpa_mcs_tree, hf_ieee80211_wfa_ie_wpa_mcs_type, tvb, offset + 3, 1, FALSE);
      }
      offset += 4;

      /* Unicast Cipher Suites */
      proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wpa_ucs_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      ucs_count = tvb_get_letohs(tvb, offset);
      offset += 2;

      wpa_ucs_item = proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wpa_ucs_list, tvb, offset, ucs_count * 4, FALSE);
      wpa_ucs_tree = proto_item_add_subtree(wpa_ucs_item, ett_wpa_ucs_tree);
      for(i=1; i <= ucs_count; i++)
      {
        wpa_sub_ucs_item = proto_tree_add_item(wpa_ucs_tree, hf_ieee80211_wfa_ie_wpa_ucs, tvb, offset, 4, FALSE);
        wpa_sub_ucs_tree = proto_item_add_subtree(wpa_sub_ucs_item, ett_wpa_sub_ucs_tree);
        proto_tree_add_item(wpa_sub_ucs_tree, hf_ieee80211_wfa_ie_wpa_ucs_oui, tvb, offset, 3, FALSE);

        /* Check if OUI is 00:50:F2 (WFA) */
        if(tvb_get_ntoh24(tvb, offset) == 0x0050F2)
        {
          proto_tree_add_item(wpa_sub_ucs_tree, hf_ieee80211_wfa_ie_wpa_ucs_wfa_type, tvb, offset+3, 1, FALSE);
          proto_item_append_text(wpa_ucs_item, " %s", wpa_ucs_return(tvb_get_ntohl(tvb, offset)));
        } else {
          proto_tree_add_item(wpa_sub_ucs_tree, hf_ieee80211_wfa_ie_wpa_ucs_type, tvb, offset+3, 1, FALSE);
        }
        offset += 4;
      }

      /* Authenticated Key Management Suites */
      proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wpa_akms_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      akms_count = tvb_get_letohs(tvb, offset);
      offset += 2;

      wpa_akms_item = proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wpa_akms_list, tvb, offset, akms_count * 4, FALSE);
      wpa_akms_tree = proto_item_add_subtree(wpa_akms_item, ett_wpa_akms_tree);
      for(i=1; i <= akms_count; i++)
      {
        wpa_sub_akms_item = proto_tree_add_item(wpa_akms_tree, hf_ieee80211_wfa_ie_wpa_akms, tvb, offset, 4, FALSE);
        wpa_sub_akms_tree = proto_item_add_subtree(wpa_sub_akms_item, ett_wpa_sub_akms_tree);
        proto_tree_add_item(wpa_sub_akms_tree, hf_ieee80211_wfa_ie_wpa_akms_oui, tvb, offset, 3, FALSE);

        /* Check if OUI is 00:50:F2 (WFA) */
        if(tvb_get_ntoh24(tvb, offset) == 0x0050F2)
        {
          proto_tree_add_item(wpa_sub_akms_tree, hf_ieee80211_wfa_ie_wpa_akms_wfa_type, tvb, offset+3, 1, FALSE);
          proto_item_append_text(wpa_akms_item, " %s", wpa_akms_return(tvb_get_ntohl(tvb, offset)));
        } else {
          proto_tree_add_item(wpa_sub_akms_tree, hf_ieee80211_wfa_ie_wpa_akms_type, tvb, offset+3, 1, FALSE);
        }
        offset += 4;
      }
      break;
    }
    case 2:   /* Wireless Multimedia Enhancements (WME) */
    {
      guint8 subtype;

      proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_subtype, tvb, offset, 1, ENC_NA);
      subtype = tvb_get_guint8(tvb, offset);
      proto_item_append_text(tree, ": %s", val_to_str(subtype, ieee802111_wfa_ie_wme_type, "Unknown %d" ));
      offset += 1;
      switch(subtype){
        case 0: /* WME Information Element */
        {
          proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_version, tvb, offset, 1, ENC_NA);
          offset += 1;
          /* WME QoS Info Field */
          offset = dissect_qos_info(tree, tvb, offset, ftype);
          break;
        }
        case 1: /* WME Parameter Element */
        {
          int i;
          proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_version, tvb, offset, 1, ENC_NA);
          offset += 1;
          /* WME QoS Info Field */
          offset = dissect_qos_info(tree, tvb, offset, ftype);
          proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_reserved, tvb, offset, 1, ENC_NA);
          offset += 1;
          /* AC Parameters */
          for(i = 0; i < 4; i++)
          {
            proto_item *ac_item, *aci_aifsn_item, *ecw_item;
            proto_tree *ac_tree, *aci_aifsn_tree, *ecw_tree;
            guint8 aci_aifsn, ecw;

            ac_item = proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_ac_parameters, tvb, offset, 4, ENC_NA);
            ac_tree = proto_item_add_subtree(ac_item, ett_wme_ac);

            /* ACI/AIFSN Field */
            aci_aifsn_item = proto_tree_add_item(ac_tree, hf_ieee80211_wfa_ie_wme_acp_aci_aifsn, tvb, offset, 1, ENC_NA);
            aci_aifsn_tree = proto_item_add_subtree(aci_aifsn_item, ett_wme_aci_aifsn);
            proto_tree_add_item(aci_aifsn_tree, hf_ieee80211_wfa_ie_wme_acp_aci, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(aci_aifsn_tree, hf_ieee80211_wfa_ie_wme_acp_acm, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(aci_aifsn_tree, hf_ieee80211_wfa_ie_wme_acp_aifsn, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(aci_aifsn_tree, hf_ieee80211_wfa_ie_wme_acp_reserved, tvb, offset, 1, ENC_NA);
            aci_aifsn = tvb_get_guint8(tvb, offset);
            proto_item_append_text(ac_item, " ACI %u (%s), ACM %s, AIFSN %u",
            (aci_aifsn & 0x60) >> 5, match_strval((aci_aifsn & 0x60) >> 5, ieee80211_wfa_ie_wme_acs_vals),
            (aci_aifsn & 0x10) ? "yes" : "no ", aci_aifsn & 0x0f);
            offset += 1;

            /* ECWmin/ECWmax field */
            ecw_item = proto_tree_add_item(ac_tree, hf_ieee80211_wfa_ie_wme_acp_ecw, tvb, offset, 1, ENC_NA);
            ecw_tree = proto_item_add_subtree(ecw_item, ett_wme_ecw);
            proto_tree_add_item(ecw_tree, hf_ieee80211_wfa_ie_wme_acp_ecw_max, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ecw_tree, hf_ieee80211_wfa_ie_wme_acp_ecw_min, tvb, offset, 1, ENC_NA);
            ecw = tvb_get_guint8(tvb, offset);
            proto_item_append_text(ac_item, ", ECWmin %u ,ECWmax %u", ecw & 0x0f, (ecw & 0xf0) >> 4 );
            offset += 1;

            /* TXOP Limit */
            proto_tree_add_item(ac_tree, hf_ieee80211_wfa_ie_wme_acp_txop_limit, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(ac_item, ", TXOP %u", tvb_get_letohs(tvb, offset));
            offset += 2;
          }
          break;
        }
        case 3:   /* WME TSPEC Element */
        {

            proto_item *tsinfo_item;
            proto_tree *tsinfo_tree;

            tsinfo_item = proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_tsinfo, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            tsinfo_tree = proto_item_add_subtree(tsinfo_item, ett_tsinfo_tree);

            proto_tree_add_item(tsinfo_tree, hf_ieee80211_wfa_ie_wme_tspec_tsinfo_tid, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tsinfo_tree, hf_ieee80211_wfa_ie_wme_tspec_tsinfo_direction, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tsinfo_tree, hf_ieee80211_wfa_ie_wme_tspec_tsinfo_psb, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tsinfo_tree, hf_ieee80211_wfa_ie_wme_tspec_tsinfo_up, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tsinfo_tree, hf_ieee80211_wfa_ie_wme_tspec_tsinfo_reserved, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_nor_msdu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_max_msdu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_min_srv, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_max_srv, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_inact_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_susp_int, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_srv_start, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_min_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_mean_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_peak_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_burst_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_delay_bound, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_min_phy, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_surplus, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_ieee80211_wfa_ie_wme_tspec_medium, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

          break;
        }
        default:
          /* No default Action */
        break;
      } /* End switch(subtype) */
      break;
    }
    case 4: /* WPS: Wifi Protected Setup */
    {
      dissect_wps_tlvs(tree, tvb, offset, tag_len-4, NULL);
    }
    break;
    default:
      /* No default Action...*/
    break;
  } /* End switch(type) */

  return offset;
}
