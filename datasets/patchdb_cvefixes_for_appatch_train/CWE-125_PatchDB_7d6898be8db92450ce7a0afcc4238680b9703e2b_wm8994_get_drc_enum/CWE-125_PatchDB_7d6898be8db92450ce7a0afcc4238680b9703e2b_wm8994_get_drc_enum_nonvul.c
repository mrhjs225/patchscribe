static int wm8994_get_drc_enum(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_value *ucontrol)
{
    struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
    struct wm8994_priv *wm8994 = snd_soc_codec_get_drvdata(codec);
    int drc = wm8994_get_drc(kcontrol->id.name);
    if (drc < 0)
    {
        return drc;
    }
    ucontrol->value.enumerated.item[0] = wm8994->drc_cfg[drc];
    return 0;
}