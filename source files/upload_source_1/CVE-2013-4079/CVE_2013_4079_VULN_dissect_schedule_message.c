static void
CVE_2013_4079_VULN_dissect_schedule_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree)
{
    guint8      octet1, i, j, k = 0;
    guint8      len, sched_begin, sched_end, new_slots[48];
    guint8      offset          = 0;
    gboolean    valid_message   = TRUE;
    guint16     other_slots[48];
    proto_item *item            = NULL, *schedule_item = NULL;
    proto_tree *sched_tree      = NULL, *sched_subtree = NULL;

    len = tvb_length(tvb);

    col_append_str(pinfo->cinfo, COL_INFO, " CBCH Schedule Message ");

    schedule_item = proto_tree_add_protocol_format(top_tree, proto_cbch, tvb, 0, len,
                                                   "GSM CBCH Schedule Message");

    sched_tree = proto_item_add_subtree(schedule_item, ett_schedule_msg);

    proto_tree_add_item(sched_tree, hf_gsm_cbch_sched_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet1 = tvb_get_guint8(tvb, offset);
    if (0 == (octet1 & 0xC0))
    {
        sched_begin = octet1 & 0x3F;
        proto_tree_add_item(sched_tree, hf_gsm_cbch_sched_begin_slot, tvb, offset++, 1, ENC_BIG_ENDIAN);
        if (1 == sched_begin)
        {
            proto_tree_add_text(sched_tree, tvb, offset - 1, 1, "(apparently) Scheduled Scheduling Message");
        }
        else if ((2 <= sched_begin) && (48 >= sched_begin))
        {
            proto_tree_add_text(sched_tree, tvb, offset - 1, 1, "(apparently) Unscheduled Scheduling Message");
        }
        else
        {
            proto_tree_add_text(sched_tree, tvb, offset - 1, 1, "Begin Slot Number out of range: ignoring message");
            valid_message = FALSE;
        }
        proto_tree_add_item(sched_tree, hf_gsm_cbch_sched_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
        sched_end = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sched_tree, hf_gsm_cbch_sched_end_slot, tvb, offset++, 1, ENC_BIG_ENDIAN);
        if (sched_end < sched_begin)
        {
            proto_tree_add_text(sched_tree, tvb, offset - 1, 1, "End Slot Number less than Begin Slot Number: ignoring message");
            valid_message = FALSE;
        }

        if (valid_message)
        {
            /* build an array of new messages */
            memset(&new_slots,   0xFF, sizeof(new_slots));
            memset(&other_slots, 0xFF, sizeof(other_slots));

            /* iterate over the octets */
            for (i=0; i<6; i++)
            {
                octet1 = tvb_get_guint8(tvb, offset++);

                /* iterate over the bits */
                for (j=0; j<8; j++)
                {
                    if (octet1 & (0x80>>j))
                    {
                        new_slots[k++] = (i<<3) + j + 1;
                    }
                }
            }
            /* print the array of new messages */
            item = proto_tree_add_text(sched_tree, tvb, offset-6, 6, "This schedule contains %d slots with new messages", k);
            sched_subtree = proto_item_add_subtree(item, ett_schedule_new_msg);
            for (i=0; i<k; i++)
            {
                DISSECTOR_ASSERT(new_slots[i] < 48);
                octet1 = tvb_get_guint8(tvb, offset);
                if ((octet1 & 0x80) == 0x80)
                {
                    /* MDT 1 */
                    guint8 octet2;
                    guint16 msg_id;

                    octet2 = tvb_get_guint8(tvb, offset + 1);
                    msg_id = ((octet1 &0x7F) << 8) + octet2;
                    proto_tree_add_text(sched_subtree, tvb, offset, 2,
                                        "Slot: %d, Message ID: %d, First transmission of an SMSCB within the Schedule Period",
                                        new_slots[i], msg_id);
                    offset +=2;
                    other_slots[new_slots[i] - 1] = msg_id;
                }
                else if ((octet1 & 0xC0) == 0)
                {
                    /* MDT 00 */
                    if (octet1 < new_slots[i])
                    {
                        proto_tree_add_text(sched_subtree, tvb, offset++, 1,
                                            "Slot: %d, Message ID: %d, Repeat of Slot %d",
                                            new_slots[i], other_slots[octet1 - 1], octet1);
                        other_slots[new_slots[i] - 1] = other_slots[octet1 - 1];
                    }
                    else
                    {
                        proto_tree_add_text(sched_subtree, tvb, offset++, 1,
                                            "Slot: %d, Apparent forward reference to slot %d",
                                            new_slots[i], octet1);
                    }
                }
                else if (octet1 == 0x40)
                {
                    /* MDT 010000000 */
                    proto_tree_add_text(sched_subtree, tvb, offset++, 1, "Slot: %d Free Message Slot, optional reading", new_slots[k]);
                    other_slots[new_slots[i] - 1] = 0xFFFE;
                }
                else if (octet1 == 0x41)
                {
                    /* MDT 010000001 */
                    proto_tree_add_text(sched_subtree, tvb, offset++, 1, "Slot: %d Free Message Slot, reading advised", new_slots[k]);
                    other_slots[new_slots[i] - 1] = 0xFFFE;
                }
                else
                {
                    /* reserved MDT */
                    proto_tree_add_text(sched_subtree, tvb, offset, 1, "Slot: %d reserved MDT: %x", new_slots[k], octet1);
                    other_slots[new_slots[i] - 1] = 0xFFFE;
                }
            }
            proto_item_set_end(item, tvb, offset);

            /* print schedule of other messages */
            item = proto_tree_add_text(sched_tree, tvb, offset, 0, "Other message slots in this schedule");
            sched_subtree = proto_item_add_subtree(item, ett_schedule_new_msg);
            for (k=0; offset<len; j++)
            {
                while ((other_slots[k]!=0xFFFF) && (k<sched_end))
                {
                    k++;
                }
                if (k >= sched_end)
                    break;

                octet1 = tvb_get_guint8(tvb, offset);
                if ((octet1 & 0x80) == 0x80)
                {
                    if ((offset+1)<len)
                    {
                        /* MDT 1 */
                        guint8  octet2;
                        guint16 msg_id;

                        octet2 = tvb_get_guint8(tvb, offset + 1);
                        msg_id = ((octet1 &0x7F) << 8) + octet2;
                        other_slots[k] = msg_id;
                        proto_tree_add_text(sched_subtree, tvb, offset, 2,
                                            "Slot: %d, Message: %d, First transmission of an SMSCB within the Schedule Period",
                                            ++k, msg_id);
                        offset +=2;
                    }
                }
                else if ((octet1 & 0xC0) == 0)
                {
                    /* MDT 00 */
                    if (octet1 < k)
                    {
                        other_slots[k] = other_slots[octet1 - 1];
                        proto_tree_add_text(sched_subtree, tvb, offset++, 1,
                                            "Slot: %d, Message ID: %d, Repeat of Slot %d",
                                            ++k, other_slots[octet1 - 1], octet1);
                    }
                    else
                    {
                        proto_tree_add_text(sched_subtree, tvb, offset++, 1,
                                            "Slot: %d, Apparent forward reference to slot %d",
                                            ++k, octet1);
                    }
                }
                else if (octet1 == 0x40)
                {
                    /* MDT 010000000 */
                    proto_tree_add_text(sched_subtree, tvb, offset++, 1, "Slot: %d Free Message Slot, optional reading", ++k);
                }
                else if (octet1 == 0x41)
                {
                    /* MDT 010000001 */
                    proto_tree_add_text(sched_subtree, tvb, offset++, 1, "Slot: %d Free Message Slot, reading advised", ++k);
                }
                else
                {
                    /* reserved MDT */
                    proto_tree_add_text(sched_subtree, tvb, offset, 1, "Slot: %d reserved MDT: %x", ++k, octet1);
                }
            }
            proto_item_set_end(item, tvb, offset);
            proto_tree_add_text(sched_tree, tvb, offset, -1, "Padding");
        }
    }
}
