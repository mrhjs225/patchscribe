static int wm8994_get_retune_mobile_enum(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_value *ucontrol)
{
    struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
    struct wm8994_priv *wm8994 = snd_soc_codec_get_drvdata(codec);
    int block = wm8994_get_retune_mobile_block(kcontrol->id.name);
    if (block < 0)
    {
        return block;
    }
    ucontrol->value.enumerated.item[0] = wm8994->retune_mobile_cfg[block];
    return 0;
}