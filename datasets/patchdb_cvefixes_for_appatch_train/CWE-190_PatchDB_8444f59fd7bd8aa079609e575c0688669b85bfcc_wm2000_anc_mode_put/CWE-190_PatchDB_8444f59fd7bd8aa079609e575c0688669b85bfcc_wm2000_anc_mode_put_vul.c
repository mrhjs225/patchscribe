static int wm2000_anc_mode_put(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_value *ucontrol)
{
    struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
    struct wm2000_priv *wm2000 = dev_get_drvdata(codec->dev);
    int anc_active = ucontrol->value.integer.value[0];
    int ret;
    if (anc_active > 1)
    {
        return -EINVAL;
    }
    mutex_lock(&wm2000->lock);
    wm2000->anc_active = anc_active;
    ret = wm2000_anc_set_mode(wm2000);
    mutex_unlock(&wm2000->lock);
    return ret;
}