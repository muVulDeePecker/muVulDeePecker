static void
CVE_2011_4101_VULN_dissect_infiniband_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean starts_with_grh)
{
    /* Top Level Item */
    proto_item *infiniband_packet = NULL;

    /* The Headers Subtree */
    proto_tree *all_headers_tree = NULL;

    /* LRH - Local Route Header */
    proto_tree *local_route_header_tree = NULL;
    proto_item *local_route_header_item = NULL;

    /* GRH - Global Route Header */
    proto_tree *global_route_header_tree = NULL;
    proto_item *global_route_header_item = NULL;

    /* BTH - Base Transport header */
    proto_tree *base_transport_header_tree = NULL;
    proto_item *base_transport_header_item = NULL;

    /* Raw Data */
    proto_tree *RAWDATA_header_tree;
    proto_item *RAWDATA_header_item;
    guint8 lnh_val = 0;             /* Link Next Header Value */
    gint offset = 0;                /* Current Offset */

    /* General Variables */
    gboolean bthFollows = 0;        /* Tracks if we are parsing a BTH.  This is a significant decision point */
    guint8 virtualLane = 0;         /* IB VirtualLane.  Keyed off of for detecting subnet admin/management */
    guint8 opCode = 0;              /* OpCode from BTH header. */
    gint32 nextHeaderSequence = -1; /* defined by this dissector. #define which indicates the upcoming header sequence from OpCode */
    guint16 payloadLength = 0;      /* Payload Length should it exist */
    guint8 nxtHdr = 0;              /* Keyed off for header dissection order */
    guint16 packetLength = 0;       /* Packet Length.  We track this as tvb_length - offset.   */
                                    /*  It provides the parsing methods a known size            */
                                    /*   that must be available for that header.                */
    struct e_in6_addr SRCgid;       /* Structures to hold GIDs should we need them */
    struct e_in6_addr DSTgid;
    gint crc_length = 0;

    /* allocate space for source/destination addresses. we will fill them in later */
    src_addr = ep_alloc(ADDR_MAX_LEN);
    dst_addr = ep_alloc(ADDR_MAX_LEN);

    pinfo->srcport = pinfo->destport = 0xffffffff;  /* set the src/dest QPN to something impossible instead of the default 0,
                                                       so we don't mistake it for a MAD. (QP is only 24bit, so can't be 0xffffffff)*/

    /* add any code that should only run the first time the packet is dissected here: */
    if (!pinfo->fd->flags.visited)
    {
        pinfo->ptype = PT_IBQP;     /* set the port-type for this packet to be Infiniband QP number */
    }

    /* Mark the Packet type as Infiniband in the wireshark UI */
    /* Clear other columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "InfiniBand");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Get the parent tree from the ERF dissector.  We don't want to nest under ERF */
    if(tree && tree->parent)
    {
        /* Set the normal tree outside of ERF */
        tree = tree->parent;
        /* Set a global reference for nested protocols */
        top_tree = tree;
    }

    /* The "quick-dissection" code in dissect_general_info skips lots of the recently-added code
       for saving context etc. It is no longer viable to maintain two code branches, so we have
       (temporarily?) disabled the second one. All dissection now goes through the full branch,
       using a NULL tree pointer if this is not a full dissection call. Take care not to dereference
       the tree pointer or any subtree pointers you create using it and you'll be fine. */
    if(0 && !tree)
    {
        /* If no packet details are being dissected, extract some high level info for the packet view */
        /* Assigns column values rather than full tree population */
        dissect_general_info(tvb, offset, pinfo, starts_with_grh);
        return;
    }

    /* Top Level Packet */
    infiniband_packet = proto_tree_add_item(tree, proto_infiniband, tvb, offset, -1, FALSE);

    /* Headers Level Tree */
    all_headers_tree = proto_item_add_subtree(infiniband_packet, ett_all_headers);

    if (starts_with_grh) {
        /* this is a RoCE packet, skip LRH parsing */
        lnh_val = IBA_GLOBAL;
        packetLength = tvb_get_ntohs(tvb, 4);   /* since we have no LRH to get PktLen from, use that of the GRH */
        goto skip_lrh;
    }

    /* Local Route Header Subtree */
    local_route_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_LRH, tvb, offset, 8, FALSE);
    proto_item_set_text(local_route_header_item, "%s", "Local Route Header");
    local_route_header_tree = proto_item_add_subtree(local_route_header_item, ett_lrh);

    proto_tree_add_item(local_route_header_tree, hf_infiniband_virtual_lane,            tvb, offset, 1, FALSE);


    /* Get the Virtual Lane.  We'll use this to identify Subnet Management and Subnet Administration Packets. */
    virtualLane =  tvb_get_guint8(tvb, offset);
    virtualLane = virtualLane & 0xF0;


    proto_tree_add_item(local_route_header_tree, hf_infiniband_link_version,            tvb, offset, 1, FALSE); offset+=1;
    proto_tree_add_item(local_route_header_tree, hf_infiniband_service_level,           tvb, offset, 1, FALSE);

    proto_tree_add_item(local_route_header_tree, hf_infiniband_reserved2,               tvb, offset, 1, FALSE);
    proto_tree_add_item(local_route_header_tree, hf_infiniband_link_next_header,        tvb, offset, 1, FALSE);


    /* Save Link Next Header... This tells us what the next header is. */
    lnh_val =  tvb_get_guint8(tvb, offset);
    lnh_val = lnh_val & 0x03;
    offset+=1;


    proto_tree_add_item(local_route_header_tree, hf_infiniband_destination_local_id,    tvb, offset, 2, FALSE);


    /* Set destination in packet view. */
    *((guint16*) dst_addr) = tvb_get_ntohs(tvb, offset);
    SET_ADDRESS(&pinfo->dst, AT_IB, sizeof(guint16), dst_addr);

    offset+=2;

    proto_tree_add_item(local_route_header_tree, hf_infiniband_reserved5,               tvb, offset, 2, FALSE);

    packetLength = tvb_get_ntohs(tvb, offset); /* Get the Packet Length. This will determine payload size later on. */
    packetLength = packetLength & 0x07FF;      /* Mask off top 5 bits, they are reserved */
    packetLength = packetLength * 4;           /* Multiply by 4 to get true byte length. This is by specification.  */
                                               /*   PktLen is size in 4 byte words (byteSize /4). */

    proto_tree_add_item(local_route_header_tree, hf_infiniband_packet_length,           tvb, offset, 2, FALSE); offset+=2;
    proto_tree_add_item(local_route_header_tree, hf_infiniband_source_local_id,         tvb, offset, 2, FALSE);

    /* Set Source in packet view. */
    *((guint16*) src_addr) = tvb_get_ntohs(tvb, offset);
    SET_ADDRESS(&pinfo->src, AT_IB, sizeof(guint16), src_addr);

    offset+=2;
    packetLength -= 8; /* Shave 8 bytes for the LRH. */

skip_lrh:

    /* Key off Link Next Header.  This tells us what High Level Data Format we have */
    switch(lnh_val)
    {
        case IBA_GLOBAL:
            global_route_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_GRH, tvb, offset, 40, FALSE);
            proto_item_set_text(global_route_header_item, "%s", "Global Route Header");
            global_route_header_tree = proto_item_add_subtree(global_route_header_item, ett_grh);

            proto_tree_add_item(global_route_header_tree, hf_infiniband_ip_version,         tvb, offset, 1, FALSE);
            proto_tree_add_item(global_route_header_tree, hf_infiniband_traffic_class,      tvb, offset, 2, FALSE);
            proto_tree_add_item(global_route_header_tree, hf_infiniband_flow_label,         tvb, offset, 4, FALSE); offset += 4;

            payloadLength = tvb_get_ntohs(tvb, offset);

            proto_tree_add_item(global_route_header_tree, hf_infiniband_payload_length,     tvb, offset, 2, FALSE); offset += 2;

            nxtHdr = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(global_route_header_tree, hf_infiniband_next_header,        tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(global_route_header_tree, hf_infiniband_hop_limit,          tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(global_route_header_tree, hf_infiniband_source_gid,         tvb, offset, 16, FALSE);

            tvb_get_ipv6(tvb, offset, &SRCgid);

            /* set source GID in packet view*/
            memcpy(src_addr, &SRCgid, GID_SIZE);
            SET_ADDRESS(&pinfo->src, AT_IB, GID_SIZE, src_addr);

            offset += 16;

            proto_tree_add_item(global_route_header_tree, hf_infiniband_destination_gid,    tvb, offset, 16, FALSE);

            tvb_get_ipv6(tvb, offset, &DSTgid);

            /* set destination GID in packet view*/
            memcpy(dst_addr, &DSTgid, GID_SIZE);
            SET_ADDRESS(&pinfo->dst, AT_IB, GID_SIZE, dst_addr);

            offset += 16;
            packetLength -= 40; /* Shave 40 bytes for GRH */

            if(nxtHdr != 0x1B)
            {
                /* Some kind of packet being transported globally with IBA, but locally it is not IBA - no BTH following. */
                break;
            }
            /* otherwise fall through and start parsing BTH */
        case IBA_LOCAL:
            bthFollows = TRUE;
            base_transport_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_BTH, tvb, offset, 12, FALSE);
            proto_item_set_text(base_transport_header_item, "%s", "Base Transport Header");
            base_transport_header_tree = proto_item_add_subtree(base_transport_header_item, ett_bth);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_opcode,                       tvb, offset, 1, FALSE);

            /* Get the OpCode - this tells us what headers are following */
            opCode = tvb_get_guint8(tvb, offset);
            col_append_str(pinfo->cinfo, COL_INFO, val_to_str((guint32)opCode, OpCodeMap, "Unknown OpCode"));
            offset +=1;

            proto_tree_add_item(base_transport_header_tree, hf_infiniband_solicited_event,              tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_migreq,                       tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_pad_count,                    tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_transport_header_version,     tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_partition_key,                tvb, offset, 2, FALSE); offset +=2;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_reserved8,                    tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_destination_qp,               tvb, offset, 3, FALSE);
            pinfo->destport = tvb_get_ntoh24(tvb, offset); offset +=3;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_acknowledge_request,          tvb, offset, 1, FALSE);
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_reserved7,                    tvb, offset, 1, FALSE); offset +=1;
            proto_tree_add_item(base_transport_header_tree, hf_infiniband_packet_sequence_number,       tvb, offset, 3, FALSE); offset +=3;


            packetLength -= 12; /* Shave 12 for Base Transport Header */

        break;
        case IP_NON_IBA:
            /* Raw IPv6 Packet */
            g_snprintf(dst_addr,  ADDR_MAX_LEN, "IPv6 over IB Packet");
            SET_ADDRESS(&pinfo->dst,  AT_STRINGZ, (int)strlen(dst_addr)+1, dst_addr);

            parse_IPvSix(all_headers_tree, tvb, &offset, pinfo);
            break;
        case RAW:
            parse_RWH(all_headers_tree, tvb, &offset, pinfo);
            break;
        default:
            /* Unknown Packet */
            RAWDATA_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_raw_data, tvb, offset, -1, FALSE);
            proto_item_set_text(RAWDATA_header_item, "%s", "Unknown Raw Data - IB Encapsulated");
            RAWDATA_header_tree = proto_item_add_subtree(RAWDATA_header_item, ett_rawdata);
            break;
    }

    /* Base Transport header is hit quite often, however it is alone since it is the exception not the rule */
    /* Only IBA Local packets use it */
    if(bthFollows)
    {
        /* Find our next header sequence based on the Opcode
        * Each case decrements the packetLength by the amount of bytes consumed by each header.
        * The find_next_header_sequence method could be used to automate this.
        * We need to keep track of this so we know much data to mark as payload/ICRC/VCRC values. */

        transport_type = (opCode & 0xE0) >> 5;   /* save transport type for identifying EoIB payloads later... */
        nextHeaderSequence = find_next_header_sequence((guint32) opCode);

        /* find_next_header_sequence gives us the DEFINE value corresponding to the header order following */
        /* Enumerations are named intuitively, e.g. RDETH DETH PAYLOAD means there is an RDETH Header, DETH Header, and a packet payload */
        switch(nextHeaderSequence)
        {
            case RDETH_DETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_RETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 16; /* RETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_IMMDT_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_RETH_IMMDT_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_RETH(all_headers_tree, tvb, &offset);
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 16; /* RETH */
                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_DETH_RETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 16; /* RETH */

                break;
            case RDETH_AETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 4; /* AETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_PAYLD:
                parse_RDETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RDETH_AETH:
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 4; /* AETH */


                break;
            case RDETH_AETH_ATOMICACKETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_AETH(all_headers_tree, tvb, &offset);
                parse_ATOMICACKETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 4; /* AETH */
                packetLength -= 8; /* AtomicAckETH */


                break;
            case RDETH_DETH_ATOMICETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_ATOMICETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */
                packetLength -= 28; /* AtomicETH */

                break;
            case RDETH_DETH:
                parse_RDETH(all_headers_tree, tvb, &offset);
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);

                packetLength -= 4; /* RDETH */
                packetLength -= 8; /* DETH */

                break;
            case DETH_PAYLD:
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);

                packetLength -= 8; /* DETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case PAYLD:

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case IMMDT_PAYLD:
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RETH_PAYLD:
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 16; /* RETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case RETH:
                parse_RETH(all_headers_tree, tvb, &offset);

                packetLength -= 16; /* RETH */

                break;
            case AETH_PAYLD:
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* AETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case AETH:
                parse_AETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* AETH */

                break;
            case AETH_ATOMICACKETH:
                parse_AETH(all_headers_tree, tvb, &offset);
                parse_ATOMICACKETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* AETH */
                packetLength -= 8; /* AtomicAckETH */

                break;
            case ATOMICETH:
                parse_ATOMICETH(all_headers_tree, tvb, &offset);

                packetLength -= 28; /* AtomicETH */

                break;
            case IETH_PAYLD:
                parse_IETH(all_headers_tree, tvb, &offset);

                packetLength -= 4; /* IETH */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            case DETH_IMMDT_PAYLD:
                parse_DETH(all_headers_tree, pinfo, tvb, &offset);
                parse_IMMDT(all_headers_tree, tvb, &offset);

                packetLength -= 8; /* DETH */
                packetLength -= 4; /* IMMDT */

                parse_PAYLOAD(all_headers_tree, pinfo, tvb, &offset, packetLength);
                break;
            default:
                parse_VENDOR(all_headers_tree, tvb, &offset);
                break;

        }

    }
    /* Display the ICRC/VCRC */
    /* Doing it this way rather than in a variety of places according to the specific packet */
    /* If we've already displayed it crc_length comes out 0 */
    crc_length = tvb_reported_length_remaining(tvb, offset);
    if(crc_length == 6)
    {
        proto_tree_add_item(all_headers_tree, hf_infiniband_invariant_crc, tvb, offset, 4, FALSE); offset +=4;
        proto_tree_add_item(all_headers_tree, hf_infiniband_variant_crc,   tvb, offset, 2, FALSE); offset+=2;
    }
    else if(crc_length == 4)
    {
        proto_tree_add_item(all_headers_tree, hf_infiniband_invariant_crc, tvb, offset, 4, FALSE); offset +=4;
    }
    else if(crc_length == 2)
    {
        proto_tree_add_item(all_headers_tree, hf_infiniband_variant_crc,   tvb, offset, 2, FALSE); offset+=2;
    }

}
