qcms_transform* CVE_2013_0792_VULN_qcms_transform_create(
		qcms_profile *in, qcms_data_type in_type,
		qcms_profile *out, qcms_data_type out_type,
		qcms_intent intent)
{
	bool precache = false;

        qcms_transform *transform = transform_alloc();
        if (!transform) {
		return NULL;
	}
	if (out_type != QCMS_DATA_RGB_8 &&
                out_type != QCMS_DATA_RGBA_8) {
            assert(0 && "output type");
	    transform_free(transform);
            return NULL;
        }

	if (out->output_table_r &&
			out->output_table_g &&
			out->output_table_b) {
		precache = true;
	}

	if (qcms_supports_iccv4 && (in->A2B0 || out->B2A0 || in->mAB || out->mAB)) {
		// Precache the transformation to a CLUT 33x33x33 in size.
		// 33 is used by many profiles and works well in pratice. 
		// This evenly divides 256 into blocks of 8x8x8.
		// TODO For transforming small data sets of about 200x200 or less
		// precaching should be avoided.
		qcms_transform *result = qcms_transform_precacheLUT_float(transform, in, out, 33, in_type);
		if (!result) {
            		assert(0 && "precacheLUT failed");
			transform_free(transform);
			return NULL;
		}
		return result;
	}

	if (precache) {
		transform->output_table_r = precache_reference(out->output_table_r);
		transform->output_table_g = precache_reference(out->output_table_g);
		transform->output_table_b = precache_reference(out->output_table_b);
	} else {
		if (!out->redTRC || !out->greenTRC || !out->blueTRC) {
			qcms_transform_release(transform);
			return NO_MEM_TRANSFORM;
		}
		build_output_lut(out->redTRC, &transform->output_gamma_lut_r, &transform->output_gamma_lut_r_length);
		build_output_lut(out->greenTRC, &transform->output_gamma_lut_g, &transform->output_gamma_lut_g_length);
		build_output_lut(out->blueTRC, &transform->output_gamma_lut_b, &transform->output_gamma_lut_b_length);
		if (!transform->output_gamma_lut_r || !transform->output_gamma_lut_g || !transform->output_gamma_lut_b) {
			qcms_transform_release(transform);
			return NO_MEM_TRANSFORM;
		}
	}

        if (in->color_space == RGB_SIGNATURE) {
		struct matrix in_matrix, out_matrix, result;

		if (in_type != QCMS_DATA_RGB_8 &&
                    in_type != QCMS_DATA_RGBA_8){
                	assert(0 && "input type");
			transform_free(transform);
                	return NULL;
            	}
		if (precache) {
#ifdef X86
		    if (sse_version_available() >= 2) {
			    if (in_type == QCMS_DATA_RGB_8)
				    transform->transform_fn = qcms_transform_data_rgb_out_lut_sse2;
			    else
				    transform->transform_fn = qcms_transform_data_rgba_out_lut_sse2;

#if !(defined(_MSC_VER) && defined(_M_AMD64))
                    /* Microsoft Compiler for x64 doesn't support MMX.
                     * SSE code uses MMX so that we disable on x64 */
		    } else
		    if (sse_version_available() >= 1) {
			    if (in_type == QCMS_DATA_RGB_8)
				    transform->transform_fn = qcms_transform_data_rgb_out_lut_sse1;
			    else
				    transform->transform_fn = qcms_transform_data_rgba_out_lut_sse1;
#endif
		    } else
#endif
			{
				if (in_type == QCMS_DATA_RGB_8)
					transform->transform_fn = qcms_transform_data_rgb_out_lut_precache;
				else
					transform->transform_fn = qcms_transform_data_rgba_out_lut_precache;
			}
		} else {
			if (in_type == QCMS_DATA_RGB_8)
				transform->transform_fn = qcms_transform_data_rgb_out_lut;
			else
				transform->transform_fn = qcms_transform_data_rgba_out_lut;
		}

		//XXX: avoid duplicating tables if we can
		transform->input_gamma_table_r = build_input_gamma_table(in->redTRC);
		transform->input_gamma_table_g = build_input_gamma_table(in->greenTRC);
		transform->input_gamma_table_b = build_input_gamma_table(in->blueTRC);
		if (!transform->input_gamma_table_r || !transform->input_gamma_table_g || !transform->input_gamma_table_b) {
			qcms_transform_release(transform);
			return NO_MEM_TRANSFORM;
		}


		/* build combined colorant matrix */
		in_matrix = build_colorant_matrix(in);
		out_matrix = build_colorant_matrix(out);
		out_matrix = matrix_invert(out_matrix);
		if (out_matrix.invalid) {
			qcms_transform_release(transform);
			return NULL;
		}
		result = matrix_multiply(out_matrix, in_matrix);

		/* store the results in column major mode
		 * this makes doing the multiplication with sse easier */
		transform->matrix[0][0] = result.m[0][0];
		transform->matrix[1][0] = result.m[0][1];
		transform->matrix[2][0] = result.m[0][2];
		transform->matrix[0][1] = result.m[1][0];
		transform->matrix[1][1] = result.m[1][1];
		transform->matrix[2][1] = result.m[1][2];
		transform->matrix[0][2] = result.m[2][0];
		transform->matrix[1][2] = result.m[2][1];
		transform->matrix[2][2] = result.m[2][2];

	} else if (in->color_space == GRAY_SIGNATURE) {
		if (in_type != QCMS_DATA_GRAY_8 &&
				in_type != QCMS_DATA_GRAYA_8){
			assert(0 && "input type");
			transform_free(transform);
			return NULL;
		}

		transform->input_gamma_table_gray = build_input_gamma_table(in->grayTRC);
		if (!transform->input_gamma_table_gray) {
			qcms_transform_release(transform);
			return NO_MEM_TRANSFORM;
		}

		if (precache) {
			if (in_type == QCMS_DATA_GRAY_8) {
				transform->transform_fn = qcms_transform_data_gray_out_precache;
			} else {
				transform->transform_fn = qcms_transform_data_graya_out_precache;
			}
		} else {
			if (in_type == QCMS_DATA_GRAY_8) {
				transform->transform_fn = qcms_transform_data_gray_out_lut;
			} else {
				transform->transform_fn = qcms_transform_data_graya_out_lut;
			}
		}
	} else {
		assert(0 && "unexpected colorspace");
		transform_free(transform);
		return NULL;
	}
	return transform;
}
