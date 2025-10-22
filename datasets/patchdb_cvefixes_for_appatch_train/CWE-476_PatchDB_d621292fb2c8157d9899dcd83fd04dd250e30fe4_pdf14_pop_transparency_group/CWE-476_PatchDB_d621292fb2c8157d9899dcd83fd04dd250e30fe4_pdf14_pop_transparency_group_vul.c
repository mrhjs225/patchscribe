static int pdf14_pop_transparency_group(gs_gstate *pgs, pdf14_ctx *ctx, const pdf14_nonseparable_blending_procs_t *pblend_procs, int tos_num_color_comp, cmm_profile_t *curr_icc_profile, gx_device *dev)
{
    pdf14_buf *tos = ctx->stack;
    pdf14_buf *nos = tos->saved;
    pdf14_mask_t *mask_stack = tos->mask_stack;
    pdf14_buf *maskbuf;
    int x0, x1, y0, y1;
    byte *new_data_buf = NULL;
    int num_noncolor_planes, new_num_planes;
    int num_cols, num_rows, nos_num_color_comp;
    bool icc_match;
    gsicc_rendering_param_t rendering_params;
    gsicc_link_t *icc_link;
    gsicc_bufferdesc_t input_buff_desc;
    gsicc_bufferdesc_t output_buff_desc;
    pdf14_device *pdev = (pdf14_device *)dev;
    bool overprint = pdev->overprint;
    gx_color_index drawn_comps = pdev->drawn_comps;
    bool nonicc_conversion = true;
    nos_num_color_comp = nos->parent_color_info_procs->num_components - nos->num_spots;
    tos_num_color_comp = tos_num_color_comp - tos->num_spots;
    pdf14_debug_mask_stack_state(ctx);
    if (mask_stack == NULL)
    {
        maskbuf = NULL;
    }
    else
    {
        maskbuf = mask_stack->rc_mask->mask_buf;
    }
    if (nos == NULL)
    {
        return_error(gs_error_rangecheck);
    }
    rect_intersect(tos->dirty, tos->rect);
    rect_intersect(nos->dirty, nos->rect);
    y0 = max(tos->dirty.p.y, nos->rect.p.y);
    y1 = min(tos->dirty.q.y, nos->rect.q.y);
    x0 = max(tos->dirty.p.x, nos->rect.p.x);
    x1 = min(tos->dirty.q.x, nos->rect.q.x);
    if (ctx->mask_stack)
    {
        rc_decrement(ctx->mask_stack->rc_mask, "pdf14_pop_transparency_group");
        if (ctx->mask_stack->rc_mask == NULL)
        {
            gs_free_object(ctx->memory, ctx->mask_stack, "pdf14_pop_transparency_group");
        }
        ctx->mask_stack = NULL;
    }
    ctx->mask_stack = mask_stack;
    tos->mask_stack = NULL;
    if (tos->idle)
    {
        exit
    }
    if (maskbuf != NULL && maskbuf->data == NULL && maskbuf->alpha == 255)
    {
        exit
    }
    dump_raw_buffer(ctx->stack->rect.q.y - ctx->stack->rect.p.y, ctx->stack->rowstride, ctx->stack->n_planes, ctx->stack->planestride, ctx->stack->rowstride, "aaTrans_Group_Pop", ctx->stack->data);
    if (nos->parent_color_info_procs->icc_profile != NULL)
    {
        icc_match = (nos->parent_color_info_procs->icc_profile->hashcode != curr_icc_profile->hashcode);
    }
    else
    {
        icc_match = false;
    }
    if ((nos->parent_color_info_procs->parent_color_mapping_procs != NULL && nos_num_color_comp != tos_num_color_comp) || icc_match)
    {
        if (x0 < x1 && y0 < y1)
        {
            num_noncolor_planes = tos->n_planes - tos_num_color_comp;
            new_num_planes = num_noncolor_planes + nos_num_color_comp;
            if (nos->parent_color_info_procs->icc_profile != NULL && curr_icc_profile != NULL)
            {
                rendering_params.black_point_comp = gsBLACKPTCOMP_ON;
                rendering_params.graphics_type_tag = GS_IMAGE_TAG;
                rendering_params.override_icc = false;
                rendering_params.preserve_black = gsBKPRESNOTSPECIFIED;
                rendering_params.rendering_intent = gsPERCEPTUAL;
                rendering_params.cmm = gsCMM_DEFAULT;
                icc_link = gsicc_get_link_profile(pgs, dev, curr_icc_profile, nos->parent_color_info_procs->icc_profile, &rendering_params, pgs->memory, false);
                if (icc_link != NULL)
                {
                    nonicc_conversion = false;
                    if (!(icc_link->is_identity))
                    {
                        if (nos_num_color_comp != tos_num_color_comp)
                        {
                            new_data_buf = gs_alloc_bytes(ctx->memory, tos->planestride * new_num_planes, "pdf14_pop_transparency_group");
                            if (new_data_buf == NULL)
                            {
                                return_error(gs_error_VMerror);
                            }
                            memcpy(new_data_buf + tos->planestride * nos_num_color_comp, tos->data + tos->planestride * tos_num_color_comp, tos->planestride * num_noncolor_planes);
                        }
                        else
                        {
                            new_data_buf = tos->data;
                        }
                        num_rows = tos->rect.q.y - tos->rect.p.y;
                        num_cols = tos->rect.q.x - tos->rect.p.x;
                        gsicc_init_buffer(&input_buff_desc, tos_num_color_comp, 1, false, false, true, tos->planestride, tos->rowstride, num_rows, num_cols);
                        gsicc_init_buffer(&output_buff_desc, nos_num_color_comp, 1, false, false, true, tos->planestride, tos->rowstride, num_rows, num_cols);
                        (icc_link->procs.map_buffer)(dev, icc_link, &input_buff_desc, &output_buff_desc, tos->data, new_data_buf);
                    }
                    gsicc_release_link(icc_link);
                    if (!(icc_link->is_identity) && nos_num_color_comp != tos_num_color_comp)
                    {
                        gs_free_object(ctx->memory, tos->data, "pdf14_pop_transparency_group");
                        tos->data = new_data_buf;
                    }
                }
            }
            if (nonicc_conversion)
            {
                new_data_buf = gs_alloc_bytes(ctx->memory, tos->planestride * new_num_planes, "pdf14_pop_transparency_group");
                if (new_data_buf == NULL)
                {
                    return_error(gs_error_VMerror);
                }
                gs_transform_color_buffer_generic(tos->data, tos->rowstride, tos->planestride, tos_num_color_comp, tos->rect, new_data_buf, nos_num_color_comp, num_noncolor_planes);
                gs_free_object(ctx->memory, tos->data, "pdf14_pop_transparency_group");
                tos->data = new_data_buf;
            }
            tos->n_chan = nos->n_chan;
            tos->n_planes = nos->n_planes;
            dump_raw_buffer(ctx->stack->rect.q.y - ctx->stack->rect.p.y, ctx->stack->rowstride, ctx->stack->n_chan, ctx->stack->planestride, ctx->stack->rowstride, "aCMTrans_Group_ColorConv", ctx->stack->data);
            pdf14_compose_group(tos, nos, maskbuf, x0, x1, y0, y1, nos->n_chan, nos->parent_color_info_procs->isadditive, nos->parent_color_info_procs->parent_blending_procs, false, drawn_comps, ctx->memory, dev);
        }
    }
    else
    {
        if (x0 < x1 && y0 < y1)
        {
            pdf14_compose_group(tos, nos, maskbuf, x0, x1, y0, y1, nos->n_chan, ctx->additive, pblend_procs, overprint, drawn_comps, ctx->memory, dev);
        }
    }
    exit ctx->stack = nos;
    if (ctx->smask_depth > 0 && maskbuf != NULL)
    {
        ctx->smask_blend = true;
    }
    if_debug1m('v', ctx->memory, "[v]pop buf, idle=%d\n", tos->idle);
    pdf14_buf_free(tos, ctx->memory);
    return 0;
}