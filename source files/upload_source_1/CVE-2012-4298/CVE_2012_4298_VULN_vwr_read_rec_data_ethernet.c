static void CVE_2012_4298_VULN_vwr_read_rec_data_ethernet(wtap *wth, guint8 *data_ptr, guint8 *rec, int rec_size, int IS_TX)
{
    vwr_t           *vwr = (vwr_t *)wth->priv;
    int             bytes_written = 0;              /* bytes output to buf so far */
    register int    i;                              /* temps */
    register guint8 *s_ptr, *m_ptr;                 /* stats and MPDU pointers */
    gint16          msdu_length,actual_octets;      /* octets in frame */
    guint8          flow_seq;                       /* seqnum */
    guint64         s_time = LL_ZERO, e_time = LL_ZERO; /* start/end */
                                                        /* times, nsec */
    guint32         latency = 0;
    guint64         start_time, s_sec, s_usec = LL_ZERO; /* start time, sec + usec */
    guint64         end_time;                            /* end time */
    guint16         l4id, info, validityBits;            /* INFO/ERRORS fields in stats */
    guint32         errors;
    guint16         vc_id;                          /* VC ID, total (incl of aggregates) */
    guint32         flow_id, d_time;                /* packet duration */
    int             f_flow;                         /* flags: flow valid */
    guint32         frame_type;                     /* frame type field */
    stats_ethernettap_fields    etap_hdr;           /* VWR ethernettap header */
    stats_common_fields common_hdr;                 /* VWR common header */
    guint16         e_hdr_len;                      /* length of ethernettap headers */
    int             mac_len, sig_off, pay_off;      /* MAC header len, signature offset */
    guint64         sig_ts, tsid;                   /* 32 LSBs of timestamp in signature */
    guint64         delta_b;    /* Used for calculating latency */

    /* calculate the start of the statistics block in the buffer */
    /* also get a bunch of fields from the stats block */
    m_ptr = &(rec[0]);                              /* point to the data block */
    s_ptr = &(rec[rec_size - vwr->STATS_LEN]);      /* point to the stats block */
    
    msdu_length = pntohs(&s_ptr[vwr->OCTET_OFF]);
    actual_octets = msdu_length;
    /* sanity check the msdu_length field to determine if it is OK (or segfaults result) */
    /* if it's greater, then truncate to the indicated message length */
    if (msdu_length > (rec_size - (int)vwr->STATS_LEN)) {
        msdu_length = (rec_size - (int)vwr->STATS_LEN);
    }

    vc_id = pntohs(&s_ptr[vwr->VCID_OFF]) & vwr->VCID_MASK;
    flow_seq = s_ptr[vwr->FLOWSEQ_OFF];
    frame_type = pntohl(&s_ptr[vwr->FRAME_TYPE_OFF]);

    if (vwr->FPGA_VERSION == vVW510024_E_FPGA) {
        validityBits = pntohs(&s_ptr[vwr->VALID_OFF]);
        f_flow = validityBits & vwr->FLOW_VALID;

        mac_len = (validityBits & vwr->IS_VLAN) ? 16 : 14;           /* MAC hdr length based on VLAN tag */


        errors = pntohs(&s_ptr[vwr->ERRORS_OFF]);
    }
    else {
        f_flow = s_ptr[vwr->VALID_OFF] & vwr->FLOW_VALID;
        mac_len = (frame_type & vwr->IS_VLAN) ? 16 : 14;             /* MAC hdr length based on VLAN tag */


        /*for older fpga errors is only represented by 16 bits)*/
        errors = pntohs(&s_ptr[vwr->ERRORS_OFF]);
    }

    info = pntohs(&s_ptr[vwr->INFO_OFF]);
    /*  24 LSBs */
    flow_id = pntoh24(&s_ptr[vwr->FLOWID_OFF]);

    /* for tx latency is duration, for rx latency is timestamp */
    /* get 64-bit latency value */
    tsid = (s_ptr[vwr->LATVAL_OFF + 6] << 8) | (s_ptr[vwr->LATVAL_OFF + 7]);
    for (i = 0; i < 4; i++)
        tsid = (tsid << 8) | s_ptr[vwr->LATVAL_OFF + i];


    l4id = pntohs(&s_ptr[vwr->L4ID_OFF]);

    /* calculate start & end times (in sec/usec), converting 64-bit times to usec */
    /* 64-bit times are "Corey-endian" */
    s_time = pcoreytohll(&s_ptr[vwr->STARTT_OFF]);
    e_time = pcoreytohll(&s_ptr[vwr->ENDT_OFF]);

    /* find the packet duration (difference between start and end times) */
    d_time = (guint32)((e_time - s_time));  /* find diff, leaving in nsec for Ethernet */

    /* also convert the packet start time to seconds and microseconds */
    start_time = s_time / NS_IN_US;                     /* convert to microseconds first */
    s_sec = (start_time / US_IN_SEC);                   /* get the number of seconds */
    s_usec = start_time - (s_sec * US_IN_SEC);          /* get the number of microseconds */

    /* also convert the packet end time to seconds and microseconds */
    end_time = e_time / NS_IN_US;                       /* convert to microseconds first */

    if (frame_type & vwr->IS_TCP)                       /* signature offset for TCP frame */
    {
        pay_off = mac_len + 40;
    }
    else if (frame_type & vwr->IS_UDP)                  /* signature offset for UDP frame */
    {
        pay_off = mac_len + 28;
    }
    else if (frame_type & vwr->IS_ICMP)                 /* signature offset for ICMP frame */
    {
        pay_off = mac_len + 24;
    }
    else if (frame_type & vwr->IS_IGMP)                 /* signature offset for IGMPv2 frame */
    {
        pay_off = mac_len + 28;
    }
    else                                                /* signature offset for raw IP frame */
    {
        pay_off = mac_len + 20;
    }

    sig_off = find_signature(m_ptr, pay_off, flow_id, flow_seq);
    if ((m_ptr[sig_off] == 0xdd) && (sig_off + 15 <= msdu_length) && (f_flow != 0))
        sig_ts = get_signature_ts(m_ptr, sig_off);
    else
        sig_ts = 0;

    /* Set latency based on rx/tx and signature timestamp */
    if (!IS_TX) {
        if (sig_ts < s_time) {
            latency = (guint32)(s_time - sig_ts);
        } else {
            /* Account for the rollover case. Since we cannot use 0x100000000 - l_time + s_time */
            /* we look for a large difference between l_time and s_time. */
            delta_b = sig_ts - s_time;
            if (delta_b >  0x10000000) {
                latency = 0;
            } else
                latency = (guint32)delta_b;
        }
    }
    /* fill up the per-packet header (amazingly like a PCAP packet header! ;-) */
    /* frames are always wired ethernet with a wired ethernettap header */
    /* caplen is the length that is captured into the file (i.e., the written-out frame */
    /* block), and should always represent the actual number of bytes in the file */
    /* len is the length of the original packet before truncation*/
    /* the FCS is NEVER included */
    e_hdr_len = STATS_COMMON_FIELDS_LEN + STATS_ETHERNETTAP_FIELDS_LEN;
    wth->phdr.len = (actual_octets - 4) + e_hdr_len;
    wth->phdr.caplen = (msdu_length - 4) + e_hdr_len;

    wth->phdr.presence_flags = WTAP_HAS_TS;

    wth->phdr.ts.secs = (time_t)s_sec;
    wth->phdr.ts.nsecs = (long)(s_usec * 1000);
    wth->phdr.pkt_encap = WTAP_ENCAP_IXVERIWAVE;

    /* generate and copy out the ETHERNETTAP header, set the port type to 1 (Ethernet) */
    common_hdr.vw_port_type = 1;
    common_hdr.it_len = STATS_COMMON_FIELDS_LEN;
    etap_hdr.it_len = STATS_ETHERNETTAP_FIELDS_LEN;

    etap_hdr.vw_errors = (guint32)errors;
    etap_hdr.vw_info = (guint16)info;
    common_hdr.vw_msdu_length = (guint16)msdu_length;
    /*etap_hdr.vw_ip_length = (guint16)ip_len;*/

    common_hdr.vw_flowid = (guint32)flow_id;
    common_hdr.vw_vcid = (guint16)vc_id;
    common_hdr.vw_seqnum = (guint16)flow_seq;

    if (!IS_TX && (sig_ts != 0))
        common_hdr.vw_latency = (guint32)latency;
    else
        common_hdr.vw_latency = 0;
    common_hdr.vw_pktdur = (guint32)d_time;
    etap_hdr.vw_l4id = (guint32)l4id;
    etap_hdr.vw_flags = 0;
    if (IS_TX)
        etap_hdr.vw_flags |= RADIOTAP_VWF_TXF;
    if (errors & vwr->FCS_ERROR)
        etap_hdr.vw_flags |= RADIOTAP_VWF_FCSERR;
    common_hdr.vw_startt = start_time;                  /* record start & end times of frame */
    common_hdr.vw_endt = end_time;
    common_hdr.vw_sig_ts = (guint32)(sig_ts);

    etap_hdr.it_pad2 = 0;

    /* put common_hdr into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], common_hdr.vw_port_type);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_hdr.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_hdr.vw_msdu_length);
    bytes_written += 2;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 2);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_flowid);
    bytes_written += 4;
    phtoles(&data_ptr[bytes_written], common_hdr.vw_vcid);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], common_hdr.vw_seqnum);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_latency);
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_sig_ts);
    bytes_written += 4;
    phtolell(&data_ptr[bytes_written], common_hdr.vw_startt);
    bytes_written += 8;
    phtolell(&data_ptr[bytes_written], common_hdr.vw_endt);
    bytes_written += 8;
    phtolel(&data_ptr[bytes_written], common_hdr.vw_pktdur);
    bytes_written += 4;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 4);
    bytes_written += 4;

    /* put etap_hdr into the packet buffer in little-endian byte order */
    phtoles(&data_ptr[bytes_written], etap_hdr.it_len);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], etap_hdr.vw_flags);
    bytes_written += 2;
    phtoles(&data_ptr[bytes_written], etap_hdr.vw_info);
    bytes_written += 2;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 2);
    bytes_written += 2;
    phtolel(&data_ptr[bytes_written], etap_hdr.vw_errors);
    bytes_written += 4;
    phtolel(&data_ptr[bytes_written], etap_hdr.vw_l4id);
    bytes_written += 4;
    /* padding */
    memset(&data_ptr[bytes_written], 0, 4);
    bytes_written += 4;

    /* finally, copy the whole MAC frame to the packet bufffer as-is; ALWAYS exclude 4-byte FCS */
    if ( rec_size < ((int)actual_octets + (int)vwr->STATS_LEN) ) 
        /*something's been truncated, DUMP AS-IS*/
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length);
    else if (msdu_length >= 4)
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length - 4);
    else
        memcpy(&data_ptr[bytes_written], m_ptr, msdu_length);
}
