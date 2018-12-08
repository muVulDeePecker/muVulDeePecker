static guint16
CVE_2015_4652_PATCHED_de_emerg_num_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32     curr_offset;
    guint8      en_len;
	guint8      count;
	proto_tree *subtree;
	proto_item *item;
    const char *digit_str;

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

        digit_str = tvb_bcd_dig_to_wmem_packet_str(tvb, curr_offset, en_len, NULL, FALSE);
        item = proto_tree_add_string(subtree, hf_gsm_a_dtap_emergency_bcd_num, tvb, curr_offset, en_len, digit_str);

        /* Check for overdicadic digits, we used the standard digit map from tvbuff.c
                *  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e  f
                * '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?','?'
         *
         */
        if(strchr(digit_str,'?')){
			expert_add_info(pinfo, item, &ei_gsm_a_dtap_end_mark_unexpected);
        }

		curr_offset = curr_offset + en_len;
		count++;
	}

	return(len);
}
