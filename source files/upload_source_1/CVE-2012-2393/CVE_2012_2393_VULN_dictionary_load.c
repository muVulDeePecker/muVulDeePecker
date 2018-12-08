static int
CVE_2012_2393_VULN_dictionary_load(void)
{
	ddict_t* d;
	ddict_application_t* p;
	ddict_vendor_t* v;
	ddict_cmd_t* c;
	ddict_typedefn_t* t;
	ddict_avp_t* a;
	gboolean do_debug_parser = getenv("WIRESHARK_DEBUG_DIAM_DICT_PARSER") ? TRUE : FALSE;
	gboolean do_dump_dict = getenv("WIRESHARK_DUMP_DIAM_DICT") ? TRUE : FALSE;
	char* dir = ep_strdup_printf("%s" G_DIR_SEPARATOR_S "diameter" G_DIR_SEPARATOR_S, get_datafile_dir());
	const avp_type_t* type;
	const avp_type_t* octetstring = &basic_types[0];
	diam_avp_t* avp;
	GHashTable* vendors = g_hash_table_new(strcase_hash,strcase_equal);
	diam_vnd_t* vnd;
	GArray* vnd_shrt_arr = g_array_new(TRUE,TRUE,sizeof(value_string));

	build_dict.hf = g_array_new(FALSE,TRUE,sizeof(hf_register_info));
	build_dict.ett = g_ptr_array_new();
	build_dict.types = g_hash_table_new(strcase_hash,strcase_equal);
	build_dict.avps = g_hash_table_new(strcase_hash,strcase_equal);

	dictionary.vnds = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK,"diameter_vnds");
	dictionary.avps = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK,"diameter_avps");

	no_vnd.vs_cmds = g_array_new(TRUE,TRUE,sizeof(value_string));
	no_vnd.vs_avps = g_array_new(TRUE,TRUE,sizeof(value_string));

	all_cmds = g_array_new(TRUE,TRUE,sizeof(value_string));

	pe_tree_insert32(dictionary.vnds,0,&no_vnd);
	g_hash_table_insert(vendors,(gchar *)"None",&no_vnd);

	/* initialize the types hash with the known basic types */
	for (type = basic_types; type->name; type++) {
		g_hash_table_insert(build_dict.types,(gchar *)type->name,(void*)type);
	}

	/* load the dictionary */
	d = ddict_scan(dir,"dictionary.xml",do_debug_parser);
	if (d == NULL) {
		return 0;
	}

	if (do_dump_dict) ddict_print(stdout, d);

	/* populate the types */
	for (t = d->typedefns; t; t = t->next) {
		const avp_type_t* parent = NULL;
		/* try to get the parent type */

		if (t->name == NULL) {
			fprintf(stderr,"Diameter Dictionary: Invalid Type (empty name): parent==%s\n",
				t->parent ? t->parent : "(null)");
			continue;
		}


		if (g_hash_table_lookup(build_dict.types,t->name))
			continue;

		if (t->parent) {
			parent = g_hash_table_lookup(build_dict.types,t->parent);
		}

		if (!parent) parent = octetstring;

		/* insert the parent type for this type */
		g_hash_table_insert(build_dict.types,t->name,(void*)parent);
	}

	/* populate the applications */
	if ((p = d->applications)) {
		GArray* arr = g_array_new(TRUE,TRUE,sizeof(value_string));

		for (; p; p = p->next) {
			value_string item = {p->code,p->name};
			g_array_append_val(arr,item);
		}

		dictionary.applications = (void*)arr->data;
		g_array_free(arr,FALSE);
	}

	if ((v = d->vendors)) {
		for ( ; v; v = v->next) {
			value_string item = {v->code,v->name};

			if (v->name == NULL) {
				fprintf(stderr,"Diameter Dictionary: Invalid Vendor (empty name): code==%d\n",v->code);
				continue;
			}

			if (g_hash_table_lookup(vendors,v->name))
				continue;

			g_array_append_val(vnd_shrt_arr,item);

			vnd = g_malloc(sizeof(diam_vnd_t));
			vnd->code = v->code;
			vnd->vs_cmds = g_array_new(TRUE,TRUE,sizeof(value_string));
			vnd->vs_avps = g_array_new(TRUE,TRUE,sizeof(value_string));
			vnd->vs_avps_ext = NULL;
			pe_tree_insert32(dictionary.vnds,vnd->code,vnd);
			g_hash_table_insert(vendors,v->name,vnd);
		}
	}

	vnd_short_vs = (void*)vnd_shrt_arr->data;
	g_array_free(vnd_shrt_arr,FALSE);

	if ((c = d->cmds)) {
		for (; c; c = c->next) {
			if (c->vendor == NULL) {
				fprintf(stderr,"Diameter Dictionary: Invalid Vendor (empty name) for command %s\n",
					c->name ? c->name : "(null)");
				continue;
			}

			if ((vnd = g_hash_table_lookup(vendors,c->vendor))) {
				value_string item = {c->code,c->name};
				g_array_append_val(vnd->vs_cmds,item);
				/* Also add to all_cmds as used by RFC version */
				g_array_append_val(all_cmds,item);
			} else {
				fprintf(stderr,"Diameter Dictionary: No Vendor: %s\n",c->vendor);
			}
		}
	}


	for (a = d->avps; a; a = a->next) {
		ddict_enum_t* e;
		value_string* vs = NULL;
		const char* vend = a->vendor ? a->vendor : "None";
		ddict_xmlpi_t* x;
		void* avp_data = NULL;

		if (a->name == NULL) {
			fprintf(stderr,"Diameter Dictionary: Invalid AVP (empty name)\n");
			continue;
		}

		if ((vnd = g_hash_table_lookup(vendors,vend))) {
			value_string vndvs = {a->code,a->name};
			g_array_append_val(vnd->vs_avps,vndvs);
		} else {
			fprintf(stderr,"Diameter Dictionary: No Vendor: %s\n",vend);
			vnd = &unknown_vendor;
		}

		if ((e = a->enums)) {
			GArray* arr = g_array_new(TRUE,TRUE,sizeof(value_string));

			for (; e; e = e->next) {
				value_string item = {e->code,e->name};
				g_array_append_val(arr,item);
			}
			g_array_sort(arr, compare_avps);
			vs = (void*)arr->data;
		}

		type = NULL;

		for( x = d->xmlpis; x; x = x->next ) {
			if ( (strcase_equal(x->name,"avp-proto") && strcase_equal(x->key,a->name))
				 || (a->type && strcase_equal(x->name,"type-proto") && strcase_equal(x->key,a->type))
				 ) {
				static avp_type_t proto_type = {"proto", proto_avp, proto_avp, FT_UINT32, BASE_NONE, build_proto_avp};
				type =  &proto_type;

				avp_data = x->value;
				break;
			}
		}

		if ( (!type) && a->type )
			type = g_hash_table_lookup(build_dict.types,a->type);

		if (!type) type = octetstring;

		avp = type->build( type, a->code, vnd, a->name, vs, avp_data);
		if (avp != NULL) {
			g_hash_table_insert(build_dict.avps, a->name, avp);

			{
				emem_tree_key_t k[] = {
					{ 1, &(a->code) },
					{ 1, &(vnd->code) },
					{ 0 , NULL }
				};
				pe_tree_insert32_array(dictionary.avps,k,avp);
			}
		}
	}
	g_hash_table_destroy(build_dict.types);
	g_hash_table_destroy(build_dict.avps);
	g_hash_table_destroy(vendors);

	return 1;
}
