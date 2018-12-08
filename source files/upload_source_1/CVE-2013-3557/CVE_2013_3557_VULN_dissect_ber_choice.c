int
CVE_2013_3557_VULN_dissect_ber_choice(asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice_t *choice, gint hf_id, gint ett_id, gint *branch_taken)
{
    gint8 ber_class;
    gboolean pc, ind, imp_tag = FALSE;
    gint32 tag;
    guint32 len;
    const ber_choice_t *ch;
    proto_tree *tree=parent_tree;
    proto_item *item=NULL;
    int end_offset, start_offset, count;
    int hoffset = offset;
    header_field_info   *hfinfo;
    gint length, length_remaining;
    tvbuff_t *next_tvb;
    gboolean first_pass;

#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("CHOICE CVE_2013_3557_VULN_dissect_ber_choice(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("CHOICE CVE_2013_3557_VULN_dissect_ber_choice(%s) entered len:%d\n",name,tvb_length_remaining(tvb,offset));
}
}
#endif
    start_offset=offset;

    if(tvb_length_remaining(tvb,offset) == 0) {
        item = proto_tree_add_string_format(parent_tree, hf_ber_error, tvb, offset, 0, "empty_choice", "BER Error: Empty choice was found");
        expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: Empty choice was found");
        return offset;
    }

    /* read header and len for choice field */
    offset=get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
    offset=get_ber_length(tvb, offset, &len, &ind);
    end_offset = offset + len ;

    /* Some sanity checks.
     * The hf field passed to us MUST be an integer type
     */
    if(hf_id >= 0){
        hfinfo=proto_registrar_get_nth(hf_id);
        switch(hfinfo->type) {
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, len,"CVE_2013_3557_VULN_dissect_ber_choice(): Was passed a HF field that was not integer type : %s",hfinfo->abbrev);
            fprintf(stderr,"CVE_2013_3557_VULN_dissect_ber_choice(): frame:%u offset:%d Was passed a HF field that was not integer type : %s\n",actx->pinfo->fd->num,offset,hfinfo->abbrev);
            return end_offset;
        }
    }



    /* loop over all entries until we find the right choice or
       run out of entries */
    ch = choice;
    if(branch_taken){
        *branch_taken=-1;
    }
    first_pass = TRUE;
    while(ch->func || first_pass){
        if(branch_taken){
            (*branch_taken)++;
        }
        /* we reset for a second pass when we will look for choices */
        if(!ch->func) {
            first_pass = FALSE;
            ch = choice; /* reset to the beginning */
            if(branch_taken){
                *branch_taken=-1;
            }
        }

choice_try_again:
#ifdef DEBUG_BER_CHOICE
printf("CHOICE testing potential subdissector class[%p]:%d:(expected)%d  tag:%d:(expected)%d flags:%d\n",ch,ber_class,ch->ber_class,tag,ch->tag,ch->flags);
#endif
        if( (first_pass && (((ch->ber_class==ber_class)&&(ch->tag==tag))
             ||  ((ch->ber_class==ber_class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)))) ||
            (!first_pass && (((ch->ber_class == BER_CLASS_ANY) && (ch->tag == -1)))) /* we failed on the first pass so now try any choices */
        ){
            if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
                /* dissect header and len for field */
                hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
                hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
                start_offset=hoffset;
                if (ind)
                    {
                    length = len-2;
                    }
                else
                    {
                    length = len;
                    }
            }
            else
                length = end_offset- hoffset;
            /* create subtree */
            if(hf_id >= 0){
                if(parent_tree){
                    item = proto_tree_add_uint(parent_tree, hf_id, tvb, hoffset, end_offset - hoffset, ch->value);
                    tree = proto_item_add_subtree(item, ett_id);
                }
            }

            length_remaining=tvb_length_remaining(tvb, hoffset);
            if(length_remaining>length)
                length_remaining=length;

#ifdef REMOVED
            /* This is bogus and makes the OID_1.0.9506.1.1.cap file
             * in Steven J Schaeffer's email of 2005-09-12 fail to dissect
             * properly.  Maybe we should get rid of 'first_pass'
             * completely.
             * It was added as a qad workaround for some problem CMIP
             * traces anyway.
             * God, this file is a mess and it is my fault. /ronnie
             */
            if(first_pass)
                next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);
            else
                next_tvb = tvb; /* we didn't make selection on this class/tag so pass it on */
#endif
            next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);


#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("CHOICE CVE_2013_3557_VULN_dissect_ber_choice(%s) calling subdissector start_offset:%d offset:%d len:%d %02x:%02x:%02x\n",name,start_offset,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("CHOICE CVE_2013_3557_VULN_dissect_ber_choice(%s) calling subdissector len:%d\n",name,tvb_length(next_tvb));
}
}
#endif
            if (next_tvb == NULL) {
                /* Assume that we have a malformed packet. */
                THROW(ReportedBoundsError);
            }
            imp_tag = FALSE;
            if ((ch->flags & BER_FLAGS_IMPLTAG))
                imp_tag = TRUE;
            count=ch->func(imp_tag, next_tvb, 0, actx, tree, *ch->p_id);
#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE CVE_2013_3557_VULN_dissect_ber_choice(%s) subdissector ate %d bytes\n",name,count);
}
#endif
            if((count==0)&&(((ch->ber_class==ber_class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)) || !first_pass)){
                /* wrong one, break and try again */
                ch++;
#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE CVE_2013_3557_VULN_dissect_ber_choice(%s) trying again\n",name);
}
#endif
                goto choice_try_again;
            }
            if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
                if(ind)
                {
                /* we are traversing a indfinite length choice where we did not pass the tag length */
                /* we need to eat the EOC */
                    if(show_internal_ber_fields){
                        proto_tree_add_text(tree, tvb, start_offset, count+2, "CHOICE EOC");
                    }
                }
            }
            return end_offset;
        }
        ch++;
    }
    if(branch_taken){
        /* none of the branches were taken so set the param
           back to -1 */
        *branch_taken=-1;
    }

#ifdef REMOVED
    /*XXX here we should have another flag to the CHOICE to distinguish
     * between the case when we know it is a mandatory   or if the CHOICE is optional == no arm matched */

    /* oops no more entries and we still havent found
     * our guy :-(
     */
    item = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "missing_choice_field", "BER Error: This choice field was not found.");
    expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: This choice field was not found");
    return end_offset;
#endif

    return start_offset;
}
