static int
CVE_2012_1594_VULN_dissect_rsn_ie(proto_tree * tree, tvbuff_t * tvb, int offset, guint32 tag_len)
{
  proto_item *rsn_gcs_item, *rsn_pcs_item, *rsn_akms_item, *rsn_cap_item, *rsn_pmkid_item, *rsn_gmcs_item;
  proto_item *rsn_sub_pcs_item, *rsn_sub_akms_item;
  proto_tree *rsn_gcs_tree, *rsn_pcs_tree, *rsn_akms_tree, *rsn_cap_tree, *rsn_pmkid_tree, *rsn_gmcs_tree;
  proto_tree *rsn_sub_pcs_tree, *rsn_sub_akms_tree;
  guint16 i, pcs_count, akms_count, pmkid_count;
  int tag_end = offset + tag_len;

  proto_tree_add_item(tree, hf_ieee80211_rsn_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  /* 7.3.2.25.1 Cipher suites */
  rsn_gcs_item = proto_tree_add_item(tree, hf_ieee80211_rsn_gcs, tvb, offset, 4, FALSE);
  rsn_gcs_tree = proto_item_add_subtree(rsn_gcs_item, ett_rsn_gcs_tree);
  proto_tree_add_item(rsn_gcs_tree, hf_ieee80211_rsn_gcs_oui, tvb, offset, 3, FALSE);
    /* Check if OUI is 00:0F:AC (ieee80211) */
  if(tvb_get_ntoh24(tvb, offset) == 0x000FAC)
  {
    proto_tree_add_item(rsn_gcs_tree, hf_ieee80211_rsn_gcs_80211_type, tvb, offset + 3, 1, FALSE);
  } else {
    proto_tree_add_item(rsn_gcs_tree, hf_ieee80211_rsn_gcs_type, tvb, offset + 3, 1, FALSE);
  }
  offset += 4;

  proto_tree_add_item(tree, hf_ieee80211_rsn_pcs_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  pcs_count = tvb_get_letohs(tvb, offset);
  offset += 2;

  rsn_pcs_item = proto_tree_add_item(tree, hf_ieee80211_rsn_pcs_list, tvb, offset, pcs_count * 4, FALSE);
  rsn_pcs_tree = proto_item_add_subtree(rsn_pcs_item, ett_rsn_pcs_tree);
  for(i=1; i <= pcs_count; i++)
  {
    rsn_sub_pcs_item = proto_tree_add_item(rsn_pcs_tree, hf_ieee80211_rsn_pcs, tvb, offset, 4, FALSE);
    rsn_sub_pcs_tree = proto_item_add_subtree(rsn_sub_pcs_item, ett_rsn_sub_pcs_tree);
    proto_tree_add_item(rsn_sub_pcs_tree, hf_ieee80211_rsn_pcs_oui, tvb, offset, 3, FALSE);
    /* Check if OUI is 00:0F:AC (ieee80211) */
    if(tvb_get_ntoh24(tvb, offset) == 0x000FAC)
    {
      proto_tree_add_item(rsn_sub_pcs_tree, hf_ieee80211_rsn_pcs_80211_type, tvb, offset+3, 1, FALSE);
      proto_item_append_text(rsn_pcs_item, " %s", rsn_pcs_return(tvb_get_ntohl(tvb, offset)));
    } else {
      proto_tree_add_item(rsn_sub_pcs_tree, hf_ieee80211_rsn_pcs_type, tvb, offset+3, 1, FALSE);
    }
    offset += 4;
  }

  /* 7.3.2.25.2 AKM suites */
  proto_tree_add_item(tree, hf_ieee80211_rsn_akms_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  akms_count = tvb_get_letohs(tvb, offset);
  offset += 2;

  rsn_akms_item = proto_tree_add_item(tree, hf_ieee80211_rsn_akms_list, tvb, offset, akms_count * 4, FALSE);
  rsn_akms_tree = proto_item_add_subtree(rsn_akms_item, ett_rsn_akms_tree);
  for(i=1; i <= akms_count; i++)
  {
    rsn_sub_akms_item = proto_tree_add_item(rsn_akms_tree, hf_ieee80211_rsn_akms, tvb, offset, 4, FALSE);
    rsn_sub_akms_tree = proto_item_add_subtree(rsn_sub_akms_item, ett_rsn_sub_akms_tree);
    proto_tree_add_item(rsn_sub_akms_tree, hf_ieee80211_rsn_akms_oui, tvb, offset, 3, FALSE);

    /* Check if OUI is 00:0F:AC (ieee80211) */
    if(tvb_get_ntoh24(tvb, offset) == 0x000FAC)
    {
      proto_tree_add_item(rsn_sub_akms_tree, hf_ieee80211_rsn_akms_80211_type, tvb, offset+3, 1, FALSE);
      proto_item_append_text(rsn_akms_item, " %s", rsn_akms_return(tvb_get_ntohl(tvb, offset)));
    } else {
      proto_tree_add_item(rsn_sub_akms_tree, hf_ieee80211_rsn_akms_type, tvb, offset+3, 1, FALSE);
    }
    offset += 4;
  }

  /* 7.3.2.25.3 RSN capabilities */
  rsn_cap_item = proto_tree_add_item(tree, hf_ieee80211_rsn_cap, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  rsn_cap_tree = proto_item_add_subtree(rsn_cap_item, ett_rsn_cap_tree);

  proto_tree_add_item(rsn_cap_tree, hf_ieee80211_rsn_cap_preauth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(rsn_cap_tree, hf_ieee80211_rsn_cap_no_pairwise, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(rsn_cap_tree, hf_ieee80211_rsn_cap_ptksa_replay_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(rsn_cap_tree, hf_ieee80211_rsn_cap_gtksa_replay_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(rsn_cap_tree, hf_ieee80211_rsn_cap_mfpr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(rsn_cap_tree, hf_ieee80211_rsn_cap_mfpc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(rsn_cap_tree, hf_ieee80211_rsn_cap_peerkey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  if(offset >= tag_end)
  {
    return offset;
  }
  /* 7.3.2.25.4 PMKID */
  proto_tree_add_item(tree, hf_ieee80211_rsn_pmkid_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  pmkid_count = tvb_get_letohs(tvb, offset);
  offset += 2;

  rsn_pmkid_item = proto_tree_add_item(tree, hf_ieee80211_rsn_pmkid_list, tvb, offset, pmkid_count * 16, FALSE);
  rsn_pmkid_tree = proto_item_add_subtree(rsn_pmkid_item, ett_rsn_pmkid_tree);
  for(i=1; i <= pmkid_count; i++)
  {
    proto_tree_add_item(rsn_pmkid_tree, hf_ieee80211_rsn_pmkid, tvb, offset, 16, FALSE);
    offset +=16;
  }

  if(offset >= tag_end)
  {
    return offset;
  }
  /* Group Management Cipher Suite (802.11w)*/
  rsn_gmcs_item = proto_tree_add_item(tree, hf_ieee80211_rsn_gmcs, tvb, offset, 4, FALSE);
  rsn_gmcs_tree = proto_item_add_subtree(rsn_gmcs_item, ett_rsn_gmcs_tree);
  proto_tree_add_item(rsn_gmcs_tree, hf_ieee80211_rsn_gmcs_oui, tvb, offset, 3, FALSE);
  /* Check if OUI is 00:0F:AC (ieee80211) */
  if(tvb_get_ntoh24(tvb, offset) == 0x000FAC)
  {
    proto_tree_add_item(rsn_gmcs_tree, hf_ieee80211_rsn_gmcs_80211_type, tvb, offset + 3, 1, FALSE);
  } else {
    proto_tree_add_item(rsn_gmcs_tree, hf_ieee80211_rsn_gmcs_type, tvb, offset + 3, 1, FALSE);
  }
  offset += 4;

  return offset;
}
