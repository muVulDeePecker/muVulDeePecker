static void
CVE_2011_4101_VULN_dissect_infiniband_link(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Top Level Item */
    proto_item *infiniband_link_packet = NULL;

    /* The Link Subtree */
    proto_tree *link_tree = NULL;

    proto_item *operand_item = NULL;
    gint offset = 0;                /* Current Offset */
    guint8 operand;                 /* Link packet Operand */

    operand =  tvb_get_guint8(tvb, offset);
    operand = (operand & 0xF0) >> 4;

    /* Mark the Packet type as Infiniband in the wireshark UI */
    /* Clear other columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "InfiniBand Link");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
             val_to_str(operand, Operand_Description, "Unknown (0x%1x)"));

    /* Get the parent tree from the ERF dissector.  We don't want to nest under ERF */
    if(tree && tree->parent)
    {
        /* Set the normal tree outside of ERF */
        tree = tree->parent;
        /* Set a global reference for nested protocols */
        top_tree = tree;
    }

    if(!tree)
    {
        /* If no packet details are being dissected, extract some high level info for the packet view */
        /* Assigns column values rather than full tree population */
        dissect_general_info(tvb, offset, pinfo, FALSE);
        return;
    }

    /* Top Level Packet */
    infiniband_link_packet = proto_tree_add_item(tree, proto_infiniband_link, tvb, offset, -1, FALSE);

    /* Headers Level Tree */
    link_tree = proto_item_add_subtree(infiniband_link_packet, ett_link);

    operand_item = proto_tree_add_item(link_tree, hf_infiniband_link_op, tvb, offset, 2, FALSE);

    if (operand > 1) {
        proto_item_set_text(operand_item, "%s", "Reserved");
        call_dissector(data_handle, tvb, pinfo, link_tree);
    } else {
        proto_tree_add_item(link_tree, hf_infiniband_link_fctbs, tvb, offset, 2, FALSE);
        offset += 2;

        proto_tree_add_item(link_tree, hf_infiniband_link_vl, tvb, offset, 2, FALSE);
        proto_tree_add_item(link_tree, hf_infiniband_link_fccl, tvb, offset, 2, FALSE);
        offset += 2;

        proto_tree_add_item(link_tree, hf_infiniband_link_lpcrc, tvb, offset, 2, FALSE);
        offset += 2;
    }

}
