static int ass_render_event(ass_event_t *event, event_images_t *event_images)
{
    char *p;
    FT_UInt previous;
    FT_UInt num_glyphs;
    FT_Vector pen;
    unsigned code;
    FT_BBox bbox;
    int i, j;
    FT_Vector shift;
    int MarginL, MarginR, MarginV;
    int last_break;
    int alignment, halign, valign;
    int device_x = 0, device_y = 0;
    if (event->Style >= frame_context.track->n_styles)
    {
        mp_msg(MSGT_ASS, MSGL_WARN, MSGTR_LIBASS_NoStyleFound);
        return 1;
    }
    if (!event->Text)
    {
        mp_msg(MSGT_ASS, MSGL_WARN, MSGTR_LIBASS_EmptyEvent);
        return 1;
    }
    init_render_context(event);
    text_info.length = 0;
    pen.x = 0;
    pen.y = 0;
    previous = 0;
    num_glyphs = 0;
    p = event->Text;
    while (1)
    {
        {
            code = get_next_char(&p);
        }
        code &&render_context.drawing_mode;
        if (!render_context.font)
        {
            free_render_context();
            return 1;
        }
        if (code == 0)
        {
            break;
        }
        if (text_info.length >= MAX_GLYPHS)
        {
            mp_msg(MSGT_ASS, MSGL_WARN, MSGTR_LIBASS_MAX_GLYPHS_Reached, (int)(event - frame_context.track->events), event->Start, event->Duration, event->Text);
            break;
        }
        if (previous && code)
        {
            FT_Vector delta;
            delta = ass_font_get_kerning(render_context.font, previous, code);
            pen.x += delta.x * render_context.scale_x;
            pen.y += delta.y * render_context.scale_y;
        }
        shift.x = pen.x & SUBPIXEL_MASK;
        shift.y = pen.y & SUBPIXEL_MASK;
        if (render_context.evt_type == EVENT_POSITIONED)
        {
            shift.x += double_to_d6(x2scr_pos(render_context.pos_x)) & SUBPIXEL_MASK;
            shift.y -= double_to_d6(y2scr_pos(render_context.pos_y)) & SUBPIXEL_MASK;
        }
        ass_font_set_transform(render_context.font, render_context.scale_x * frame_context.font_scale_x, render_context.scale_y, &shift);
        get_outline_glyph(code, text_info.glyphs + text_info.length, &shift);
        text_info.glyphs[text_info.length].pos.x = pen.x >> 6;
        text_info.glyphs[text_info.length].pos.y = pen.y >> 6;
        pen.x += text_info.glyphs[text_info.length].advance.x;
        pen.x += double_to_d6(render_context.hspacing);
        pen.y += text_info.glyphs[text_info.length].advance.y;
        previous = code;
        text_info.glyphs[text_info.length].symbol = code;
        text_info.glyphs[text_info.length].linebreak = 0;
        for (i = 0; i < 4; ++i)
        {
            uint32_t clr = render_context.c[i];
            change_alpha(&clr, mult_alpha(_a(clr), render_context.fade), 1.);
            text_info.glyphs[text_info.length].c[i] = clr;
        }
        text_info.glyphs[text_info.length].effect_type = render_context.effect_type;
        text_info.glyphs[text_info.length].effect_timing = render_context.effect_timing;
        text_info.glyphs[text_info.length].effect_skip_timing = render_context.effect_skip_timing;
        text_info.glyphs[text_info.length].be = render_context.be;
        text_info.glyphs[text_info.length].blur = render_context.blur;
        text_info.glyphs[text_info.length].shadow = render_context.shadow;
        text_info.glyphs[text_info.length].frx = render_context.frx;
        text_info.glyphs[text_info.length].fry = render_context.fry;
        text_info.glyphs[text_info.length].frz = render_context.frz;
        ass_font_get_asc_desc(render_context.font, code, &text_info.glyphs[text_info.length].asc, &text_info.glyphs[text_info.length].desc);
        text_info.glyphs[text_info.length].asc *= render_context.scale_y;
        text_info.glyphs[text_info.length].desc *= render_context.scale_y;
        text_info.glyphs[text_info.length].hash_key.font = render_context.font;
        text_info.glyphs[text_info.length].hash_key.size = render_context.font_size;
        text_info.glyphs[text_info.length].hash_key.outline = render_context.border * 0xFFFF;
        text_info.glyphs[text_info.length].hash_key.scale_x = render_context.scale_x * 0xFFFF;
        text_info.glyphs[text_info.length].hash_key.scale_y = render_context.scale_y * 0xFFFF;
        text_info.glyphs[text_info.length].hash_key.frx = render_context.frx * 0xFFFF;
        text_info.glyphs[text_info.length].hash_key.fry = render_context.fry * 0xFFFF;
        text_info.glyphs[text_info.length].hash_key.frz = render_context.frz * 0xFFFF;
        text_info.glyphs[text_info.length].hash_key.bold = render_context.bold;
        text_info.glyphs[text_info.length].hash_key.italic = render_context.italic;
        text_info.glyphs[text_info.length].hash_key.ch = code;
        text_info.glyphs[text_info.length].hash_key.advance = shift;
        text_info.glyphs[text_info.length].hash_key.be = render_context.be;
        text_info.glyphs[text_info.length].hash_key.blur = render_context.blur;
        text_info.length++;
        render_context.effect_type = EF_NONE;
        render_context.effect_timing = 0;
        render_context.effect_skip_timing = 0;
    }
    if (text_info.length == 0)
    {
        free_render_context();
        return 1;
    }
    process_karaoke_effects();
    alignment = render_context.alignment;
    halign = alignment & 3;
    valign = alignment & 12;
    MarginL = (event->MarginL) ? event->MarginL : render_context.style->MarginL;
    MarginR = (event->MarginR) ? event->MarginR : render_context.style->MarginR;
    MarginV = (event->MarginV) ? event->MarginV : render_context.style->MarginV;
    if (render_context.evt_type != EVENT_HSCROLL)
    {
        int max_text_width;
        max_text_width = x2scr(frame_context.track->PlayResX - MarginR) - x2scr(MarginL);
        wrap_lines_smart(max_text_width);
        last_break = -1;
        for (i = 1; i < text_info.length + 1; ++i)
        {
            if ((i == text_info.length) || text_info.glyphs[i].linebreak)
            {
                int width, shift = 0;
                glyph_info_t *first_glyph = text_info.glyphs + last_break + 1;
                glyph_info_t *last_glyph = text_info.glyphs + i - 1;
                while ((last_glyph > first_glyph) && ((last_glyph->symbol == '\n') || (last_glyph->symbol == 0)))
                {
                    last_glyph--;
                }
                width = last_glyph->pos.x + d6_to_int(last_glyph->advance.x) - first_glyph->pos.x;
                if (halign == HALIGN_LEFT)
                {
                    shift = 0;
                }
                if (halign == HALIGN_RIGHT)
                {
                    shift = max_text_width - width;
                }
                if (halign == HALIGN_CENTER)
                {
                    shift = (max_text_width - width) / 2;
                }
                for (j = last_break + 1; j < i; ++j)
                {
                    text_info.glyphs[j].pos.x += shift;
                }
                last_break = i - 1;
            }
        }
    }
    else
    {
        measure_text();
    }
    compute_string_bbox(&text_info, &bbox);
    if (render_context.evt_type == EVENT_NORMAL || render_context.evt_type == EVENT_VSCROLL)
    {
        device_x = x2scr(MarginL);
    }
    if (render_context.evt_type == EVENT_HSCROLL)
    {
        if (render_context.scroll_direction == SCROLL_RL)
        {
            device_x = x2scr(frame_context.track->PlayResX - render_context.scroll_shift);
        }
        if (render_context.scroll_direction == SCROLL_LR)
        {
            device_x = x2scr(render_context.scroll_shift) - (bbox.xMax - bbox.xMin);
        }
    }
    if (render_context.evt_type == EVENT_NORMAL || render_context.evt_type == EVENT_HSCROLL)
    {
        if (valign == VALIGN_TOP)
        {
            device_y = y2scr_top(MarginV) + d6_to_int(text_info.lines[0].asc);
        }
        if (valign == VALIGN_CENTER)
        {
            int scr_y = y2scr(frame_context.track->PlayResY / 2);
            device_y = scr_y - (bbox.yMax - bbox.yMin) / 2;
        }
        else
        {
            int scr_y;
            if (valign != VALIGN_SUB)
            {
                mp_msg(MSGT_ASS, MSGL_V, "Invalid valign, supposing 0 (subtitle)\n");
            }
            scr_y = y2scr_sub(frame_context.track->PlayResY - MarginV);
            device_y = scr_y;
            device_y -= d6_to_int(text_info.height);
            device_y += d6_to_int(text_info.lines[0].asc);
        }
    }
    if (render_context.evt_type == EVENT_VSCROLL)
    {
        if (render_context.scroll_direction == SCROLL_TB)
        {
            device_y = y2scr(render_context.clip_y0 + render_context.scroll_shift) - (bbox.yMax - bbox.yMin);
        }
        if (render_context.scroll_direction == SCROLL_BT)
        {
            device_y = y2scr(render_context.clip_y1 - render_context.scroll_shift);
        }
    }
    if (render_context.evt_type == EVENT_POSITIONED)
    {
        int base_x = 0;
        int base_y = 0;
        mp_msg(MSGT_ASS, MSGL_DBG2, "positioned event at %f, %f\n", render_context.pos_x, render_context.pos_y);
        get_base_point(bbox, alignment, &base_x, &base_y);
        device_x = x2scr_pos(render_context.pos_x) - base_x;
        device_y = y2scr_pos(render_context.pos_y) - base_y;
    }
    if (render_context.evt_type == EVENT_NORMAL || render_context.evt_type == EVENT_HSCROLL || render_context.evt_type == EVENT_VSCROLL)
    {
        render_context.clip_x0 = x2scr(render_context.clip_x0);
        render_context.clip_x1 = x2scr(render_context.clip_x1);
        if (valign == VALIGN_TOP)
        {
            render_context.clip_y0 = y2scr_top(render_context.clip_y0);
            render_context.clip_y1 = y2scr_top(render_context.clip_y1);
        }
        if (valign == VALIGN_CENTER)
        {
            render_context.clip_y0 = y2scr(render_context.clip_y0);
            render_context.clip_y1 = y2scr(render_context.clip_y1);
        }
        if (valign == VALIGN_SUB)
        {
            render_context.clip_y0 = y2scr_sub(render_context.clip_y0);
            render_context.clip_y1 = y2scr_sub(render_context.clip_y1);
        }
    }
    if (render_context.evt_type == EVENT_POSITIONED)
    {
        render_context.clip_x0 = x2scr_pos(render_context.clip_x0);
        render_context.clip_x1 = x2scr_pos(render_context.clip_x1);
        render_context.clip_y0 = y2scr_pos(render_context.clip_y0);
        render_context.clip_y1 = y2scr_pos(render_context.clip_y1);
    }
    {
        FT_Vector center;
        if (render_context.have_origin)
        {
            center.x = x2scr(render_context.org_x);
            center.y = y2scr(render_context.org_y);
        }
        else
        {
            int bx = 0, by = 0;
            get_base_point(bbox, alignment, &bx, &by);
            center.x = device_x + bx;
            center.y = device_y + by;
        }
        for (i = 0; i < text_info.length; ++i)
        {
            glyph_info_t *info = text_info.glyphs + i;
            if (info->hash_key.frx || info->hash_key.fry || info->hash_key.frz)
            {
                info->hash_key.shift_x = info->pos.x + device_x - center.x;
                info->hash_key.shift_y = -(info->pos.y + device_y - center.y);
            }
            else
            {
                info->hash_key.shift_x = 0;
                info->hash_key.shift_y = 0;
            }
        }
    }
    for (i = 0; i < text_info.length; ++i)
    {
        get_bitmap_glyph(text_info.glyphs + i);
    }
    event_images->top = device_y - d6_to_int(text_info.lines[0].asc);
    event_images->height = d6_to_int(text_info.height);
    event_images->detect_collisions = render_context.detect_collisions;
    event_images->shift_direction = (valign == VALIGN_TOP) ? 1 : -1;
    event_images->event = event;
    event_images->imgs = render_text(&text_info, device_x, device_y);
    free_render_context();
    return 0;
}