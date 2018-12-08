static tvbuff_t *
CVE_2011_1138_VULN_dissect_6lowpan_hc1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint dgram_size, proto_item *length_item)
{
    gint                offset = 0;
    gint                bit_offset;
    int                 i;
    guint8              hc1_encoding;
    guint8              hc_udp_encoding = 0;
    guint8              next_header;
    proto_tree *        hc_tree = NULL;
    proto_item *        ti;
    tvbuff_t *          ipv6_tvb;
    /* IPv6 header. */
    guint8              ipv6_class;
    struct ip6_hdr      ipv6;
    struct lowpan_nhdr *nhdr_list;

    /*=====================================================
     * Parse HC Encoding Flags
     *=====================================================
     */
    /* Create a tree for the HC1 Header. */
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint16), "HC1 Encoding");
        hc_tree = proto_item_add_subtree(ti, ett_6lowpan_hc1);

        /* Get and display the pattern. */
        proto_tree_add_bits_item(hc_tree, hf_6lowpan_pattern, tvb, 0, LOWPAN_PATTERN_HC1_BITS, FALSE);
    }
    offset += sizeof(guint8);

    /* Get and display the HC1 encoding bits. */
    hc1_encoding = tvb_get_guint8(tvb, offset);
    next_header = ((hc1_encoding & LOWPAN_HC1_NEXT) >> 1);
    if (tree) {
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_source_prefix, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_SOURCE_PREFIX);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_source_ifc, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_SOURCE_IFC);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_dest_prefix, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_DEST_PREFIX);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_dest_ifc, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_DEST_IFC);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_class, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_TRAFFIC_CLASS);
        proto_tree_add_uint(hc_tree, hf_6lowpan_hc1_next, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_NEXT);
        proto_tree_add_boolean(hc_tree, hf_6lowpan_hc1_more, tvb, offset, sizeof(guint8), hc1_encoding & LOWPAN_HC1_MORE);
    }
    offset += sizeof(guint8);

    /* Get and display the HC2 encoding bits, if present. */
    if (hc1_encoding & LOWPAN_HC1_MORE) {
        if (next_header == LOWPAN_HC1_NEXT_UDP) {
            hc_udp_encoding = tvb_get_guint8(tvb, offset);
            if (tree) {
                ti = proto_tree_add_text(tree, tvb, 0, sizeof(guint8), "HC_UDP Encoding");
                hc_tree = proto_item_add_subtree(ti, ett_6lowpan_hc2_udp);
                proto_tree_add_boolean(hc_tree, hf_6lowpan_hc2_udp_src, tvb, offset, sizeof(guint8), hc_udp_encoding & LOWPAN_HC2_UDP_SRCPORT);
                proto_tree_add_boolean(hc_tree, hf_6lowpan_hc2_udp_dst, tvb, offset, sizeof(guint8), hc_udp_encoding & LOWPAN_HC2_UDP_DSTPORT);
                proto_tree_add_boolean(hc_tree, hf_6lowpan_hc2_udp_len, tvb, offset, sizeof(guint8), hc_udp_encoding & LOWPAN_HC2_UDP_LENGTH);
            }
            offset += sizeof(guint8);
        }
        else {
            /* HC1 states there are more bits, but an illegal next header was defined. */
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "HC1 more bits expected for illegal next header type.");
            return NULL;
        }
    }

    /*=====================================================
     * Parse Uncompressed IPv6 Header Fields
     *=====================================================
     */
    /*
     * And now all hell breaks loose. After the header encoding fields, we are
     * left with an assortment of optional fields from the IPv6 header,
     * depending on which fields are present or not, the headers may not be
     * aligned to an octet boundary.
     *
     * From now on we have to parse the uncompressed fields relative to a bit
     * offset.
     */
    bit_offset = offset << 3;

    /* Parse hop limit */
    ipv6.ip6_hops = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS);
    if (tree) {
        proto_tree_add_uint(tree, hf_6lowpan_hop_limit, tvb, bit_offset>>3,
                BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_HOP_LIMIT_BITS), ipv6.ip6_hops);
    }
    bit_offset += LOWPAN_IPV6_HOP_LIMIT_BITS;

    /*=====================================================
     * Parse/Decompress IPv6 Source Address
     *=====================================================
     */
    offset = bit_offset;
    if (!(hc1_encoding & LOWPAN_HC1_SOURCE_PREFIX)) {
        for (i=0; i<8; i++, bit_offset += 8) {
            ipv6.ip6_src.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(ipv6.ip6_src.bytes, lowpan_llprefix, sizeof(lowpan_llprefix));
    }
    if (!(hc1_encoding & LOWPAN_HC1_SOURCE_IFC)) {
        for (i=8; i<16; i++, bit_offset += 8) {
            ipv6.ip6_src.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    /* Try to recover the source interface identifier from the packet info. */
    else if (pinfo->src.type == AT_EUI64) {
        memcpy(&ipv6.ip6_src.bytes[8], pinfo->src.data, 8);
    }
    /* Try to recover the source interface identifier from the link layer. */
    else {
        lowpan_dlsrc_to_ifcid(pinfo, &ipv6.ip6_src.bytes[8]);
    }
    /* Display the source address. */
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_source, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), (guint8 *)&ipv6.ip6_src);
    }
    /*
     * Do not set the address columns until after defragmentation, since we have
     * to do decompression before reassembly, and changing the address will cause
     * wireshark to think that the middle fragments came from another device.
     */

    /*=====================================================
     * Parse/Decompress IPv6 Destination Address
     *=====================================================
     */
    offset = bit_offset;
    if (!(hc1_encoding & LOWPAN_HC1_DEST_PREFIX)) {
        for (i=0; i<8; i++, bit_offset += 8) {
            ipv6.ip6_dst.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    else {
        memcpy(ipv6.ip6_dst.bytes, lowpan_llprefix, sizeof(lowpan_llprefix));
    }
    if (!(hc1_encoding & LOWPAN_HC1_DEST_IFC)) {
        for (i=8; i<16; i++, bit_offset += 8) {
            ipv6.ip6_dst.bytes[i] = tvb_get_bits8(tvb, bit_offset, 8);
        }
    }
    /* Try to recover the destination interface identifier from the packet info. */
    else if (pinfo->dst.type == AT_EUI64) {
        memcpy(&ipv6.ip6_dst.bytes[8], pinfo->dst.data, 8);
    }
    /* Try to recover the source interface identifier from the link layer. */
    else {
        lowpan_dldst_to_ifcid(pinfo, &ipv6.ip6_dst.bytes[8]);
    }
    /* Display the destination address. */
    if (tree) {
        proto_tree_add_ipv6(tree, hf_6lowpan_dest, tvb, offset>>3,
                BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), (guint8 *)&ipv6.ip6_dst);
    }
    /*
     * Do not set the address columns until after defragmentation, since we have
     * to do decompression before reassembly, and changing the address will cause
     * wireshark to think that the middle fragments came from another device.
     */

    /* Parse the traffic class and flow label. */
    ipv6_class = 0;
    ipv6.ip6_flow = 0;
    if (!(hc1_encoding & LOWPAN_HC1_TRAFFIC_CLASS)) {
        /* Parse the traffic class. */
        ipv6_class = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_TRAFFIC_CLASS_BITS);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_traffic_class, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_TRAFFIC_CLASS_BITS), ipv6_class);
        }
        bit_offset += LOWPAN_IPV6_TRAFFIC_CLASS_BITS;

        /* Parse the flow label. */
        ipv6.ip6_flow = tvb_get_bits32(tvb, bit_offset, LOWPAN_IPV6_FLOW_LABEL_BITS, FALSE);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_flow_label, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_FLOW_LABEL_BITS), ipv6.ip6_flow);
        }
        bit_offset += LOWPAN_IPV6_FLOW_LABEL_BITS;
    }
    ipv6.ip6_flow = g_ntohl(ipv6.ip6_flow | (ipv6_class << LOWPAN_IPV6_FLOW_LABEL_BITS));
    ipv6.ip6_vfc = ((0x6 << 4) | (ipv6_class >> 4));

    /* Parse the IPv6 next header field. */
    if (next_header == LOWPAN_HC1_NEXT_UDP) {
        ipv6.ip6_nxt = IP_PROTO_UDP;
    }
    else if (next_header == LOWPAN_HC1_NEXT_ICMP) {
        ipv6.ip6_nxt = IP_PROTO_ICMPV6;
    }
    else if (next_header == LOWPAN_HC1_NEXT_TCP) {
        ipv6.ip6_nxt = IP_PROTO_TCP;
    }
    else {
        /* Parse the next header field. */
        ipv6.ip6_nxt = tvb_get_bits8(tvb, bit_offset, LOWPAN_IPV6_NEXT_HEADER_BITS);
        if (tree) {
            proto_tree_add_uint_format(tree, hf_6lowpan_next_header, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_IPV6_NEXT_HEADER_BITS), ipv6.ip6_nxt,
                    "Next header: %s (0x%02x)", ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);
        }
        bit_offset += LOWPAN_IPV6_NEXT_HEADER_BITS;
    }

    /*=====================================================
     * Parse and Reconstruct the UDP Header
     *=====================================================
     */
    if ((hc1_encoding & LOWPAN_HC1_MORE) && (next_header == LOWPAN_HC1_NEXT_UDP)) {
        struct udp_hdr  udp;
        gint            length;

        /* Parse the source port. */
        offset = bit_offset;
        if (hc_udp_encoding & LOWPAN_HC2_UDP_SRCPORT) {
            udp.src_port = tvb_get_bits8(tvb, bit_offset, LOWPAN_UDP_PORT_COMPRESSED_BITS) + LOWPAN_PORT_12BIT_OFFSET;
            bit_offset += LOWPAN_UDP_PORT_COMPRESSED_BITS;
        }
        else {
            udp.src_port = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_PORT_BITS, FALSE);
            bit_offset += LOWPAN_UDP_PORT_BITS;
        }
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_src, tvb, offset>>3,
                    BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), udp.src_port);
        }
        udp.src_port = g_ntohs(udp.src_port);

        /* Parse the destination port. */
        offset = bit_offset;
        if (hc_udp_encoding & LOWPAN_HC2_UDP_DSTPORT) {
            udp.dst_port = tvb_get_bits8(tvb, bit_offset, LOWPAN_UDP_PORT_COMPRESSED_BITS) + LOWPAN_PORT_12BIT_OFFSET;
            bit_offset += LOWPAN_UDP_PORT_COMPRESSED_BITS;
        }
        else {
            udp.dst_port = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_PORT_BITS, FALSE);
            bit_offset += LOWPAN_UDP_PORT_BITS;
        }
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_dst, tvb, offset>>3,
                    BITS_TO_BYTE_LEN(offset, (bit_offset-offset)), udp.dst_port);
        }
        udp.dst_port = g_ntohs(udp.dst_port);

        /* Parse the length, if present. */
        if (!(hc_udp_encoding & LOWPAN_HC2_UDP_LENGTH)) {
            udp.length = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_LENGTH_BITS, FALSE);
            if (tree) {
                proto_tree_add_uint(tree, hf_6lowpan_udp_len, tvb, bit_offset>>3,
                        BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_LENGTH_BITS), udp.length);

            }
            bit_offset += LOWPAN_UDP_LENGTH_BITS;
        }
        /* Compute the length from the fragmentation headers. */
        else if (dgram_size >= 0) {
            if (dgram_size < (gint)sizeof(struct ip6_hdr)) {
                /* Datagram size is too small */
                expert_add_info_format(pinfo, length_item, PI_MALFORMED,
                    PI_ERROR, "Length is less than IPv6 header length %u",
                    (guint)sizeof(struct ip6_hdr));
                return NULL;
            }
            udp.length = dgram_size - (gint)sizeof(struct ip6_hdr);
        }
        /* Compute the length from the tvbuff size. */
        else {
            udp.length = tvb_reported_length(tvb);
            udp.length -= BITS_TO_BYTE_LEN(0, bit_offset + LOWPAN_UDP_CHECKSUM_BITS);
            udp.length += sizeof(struct udp_hdr);
        }
        udp.length = g_ntohs(udp.length);

        /* Parse the checksum. */
        udp.checksum = tvb_get_bits16(tvb, bit_offset, LOWPAN_UDP_CHECKSUM_BITS, FALSE);
        if (tree) {
            proto_tree_add_uint(tree, hf_6lowpan_udp_checksum, tvb, bit_offset>>3,
                    BITS_TO_BYTE_LEN(bit_offset, LOWPAN_UDP_CHECKSUM_BITS), udp.checksum);
        }
        bit_offset += LOWPAN_UDP_CHECKSUM_BITS;
        udp.checksum = g_ntohs(udp.checksum);

        /* Construct the next header for the UDP datagram. */
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        length = tvb_length_remaining(tvb, offset);
        nhdr_list = (struct lowpan_nhdr *)ep_alloc(sizeof(struct lowpan_nhdr) + sizeof(struct udp_hdr) + length);
        nhdr_list->next = NULL;
        nhdr_list->proto = IP_PROTO_UDP;
        nhdr_list->length = length + sizeof(struct udp_hdr);
        nhdr_list->reported = g_ntohs(udp.length);

        /* Copy the UDP header into the buffer. */
        memcpy(LOWPAN_NHDR_DATA(nhdr_list), &udp, sizeof(struct udp_hdr));
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr_list) + sizeof(struct udp_hdr), offset, length);
    }
    /*=====================================================
     * Reconstruct the IPv6 Packet
     *=====================================================
     */
    else {
        offset = BITS_TO_BYTE_LEN(0, bit_offset);
        nhdr_list = (struct lowpan_nhdr *)ep_alloc(sizeof(struct lowpan_nhdr) + tvb_length_remaining(tvb, offset));
        nhdr_list->next = NULL;
        nhdr_list->proto = ipv6.ip6_nxt;
        nhdr_list->length = tvb_length_remaining(tvb, offset);
        if (dgram_size < 0) {
            nhdr_list->reported = tvb_reported_length_remaining(tvb, offset);
        }
        else {
            nhdr_list->reported = dgram_size - sizeof(struct ip6_hdr);
        }
        tvb_memcpy(tvb, LOWPAN_NHDR_DATA(nhdr_list), offset, nhdr_list->length);
    }

    /* Link the reassembled tvbuff together.  */
    ipv6_tvb = lowpan_reassemble_ipv6(tvb, &ipv6, nhdr_list);
    add_new_data_source(pinfo, ipv6_tvb, "Decompressed 6LoWPAN header");
    return ipv6_tvb;
} /* CVE_2011_1138_VULN_dissect_6lowpan_hc1 */
