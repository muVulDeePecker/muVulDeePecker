static guint16
CVE_2015_4652_VULN_de_emerg_num_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32     curr_offset;
	guint8      en_len, oct, i;
	guint8      count;
	guint8     *poctets;
	proto_tree *subtree;
	proto_item *item;
	gboolean    malformed_number;

	curr_offset = offset;

	count = 1;
	while ((curr_offset - offset) < len){
		/* Length of 1st Emergency Number information note 1) octet 3
		 * NOTE 1: The length contains the number of octets used to encode the
		 * Emergency Service Category Value and the Number digits.
		 */
		en_len = tvb_get_guint8(tvb, curr_offset);

		item = proto_tree_add_uint(tree, hf_gsm_a_dtap_emergency_number_information,
			tvb, curr_offset, en_len + 1, count);
		subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_EMERGENCY_NUM_LIST]);
		proto_tree_add_item(subtree, hf_gsm_a_dtap_emerg_num_info_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

		curr_offset++;
		/* 0 0 0 Emergency Service Category Value (see
		 *       Table 10.5.135d/3GPP TS 24.008
		 * Table 10.5.135d/3GPP TS 24.008: Service Category information element
		 */
		proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		curr_offset++;
		en_len--;

		poctets = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, curr_offset, en_len);

		my_dgt_tbcd_unpack(a_bigbuf, poctets, en_len, &Dgt_mbcd);

		item = proto_tree_add_string_format(subtree, hf_gsm_a_dtap_emergency_bcd_num,
			tvb, curr_offset, en_len,
			a_bigbuf,
			"BCD Digits: %s",
			a_bigbuf);

		malformed_number = FALSE;
		for(i = 0; i < en_len - 1; i++)
		{
			oct = poctets[i];
			if (((oct & 0xf0) == 0xf0) || ((oct & 0x0f) == 0x0f))
			{
				malformed_number = TRUE;
				break;
			}
		}

		oct = poctets[en_len - 1];
		if ((oct & 0x0f) == 0x0f)
			malformed_number = TRUE;

		if(malformed_number)
			expert_add_info(pinfo, item, &ei_gsm_a_dtap_end_mark_unexpected);

		curr_offset = curr_offset + en_len;
		count++;
	}

	return(len);
}
