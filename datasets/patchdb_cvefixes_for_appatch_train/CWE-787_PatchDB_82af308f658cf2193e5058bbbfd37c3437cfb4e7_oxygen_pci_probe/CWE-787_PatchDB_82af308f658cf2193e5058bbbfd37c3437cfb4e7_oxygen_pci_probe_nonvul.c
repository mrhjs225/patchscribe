int oxygen_pci_probe(struct pci_dev *pci, int index, char *id, struct module *owner, const struct pci_device_id *ids, int *get_model(struct oxygen *chip, const struct pci_device_id *id))
{
    struct snd_card *card;
    struct oxygen *chip;
    const struct pci_device_id *pci_id;
    int err;
    err = snd_card_create(index, id, owner, sizeof(*chip), &card);
    if (err < 0)
    {
        return err;
    }
    chip = card->private_data;
    chip->card = card;
    chip->pci = pci;
    chip->irq = -1;
    spin_lock_init(&chip->reg_lock);
    mutex_init(&chip->mutex);
    INIT_WORK(&chip->spdif_input_bits_work, oxygen_spdif_input_bits_changed);
    INIT_WORK(&chip->gpio_work, oxygen_gpio_changed);
    init_waitqueue_head(&chip->ac97_waitqueue);
    err = pci_enable_device(pci);
    if (err < 0)
    {
        err_card
    }
    err = pci_request_regions(pci, DRIVER);
    if (err < 0)
    {
        snd_printk(KERN_ERR "cannot reserve PCI resources\n");
        err_pci_enable
    }
    if (!(pci_resource_flags(pci, 0) & IORESOURCE_IO) || pci_resource_len(pci, 0) < OXYGEN_IO_SIZE)
    {
        snd_printk(KERN_ERR "invalid PCI I/O range\n");
        err = -ENXIO;
        err_pci_regions
    }
    chip->addr = pci_resource_start(pci, 0);
    pci_id = oxygen_search_pci_id(chip, ids);
    if (!pci_id)
    {
        err = -ENODEV;
        err_pci_regions
    }
    oxygen_restore_eeprom(chip, pci_id);
    err = get_model(chip, pci_id);
    if (err < 0)
    {
        err_pci_regions
    }
    if (chip->model.model_data_size)
    {
        chip->model_data = kzalloc(chip->model.model_data_size, GFP_KERNEL);
        if (!chip->model_data)
        {
            err = -ENOMEM;
            err_pci_regions
        }
    }
    pci_set_master(pci);
    snd_card_set_dev(card, &pci->dev);
    card->private_free = oxygen_card_free;
    oxygen_init(chip);
    chip->model.init(chip);
    err = request_irq(pci->irq, oxygen_interrupt, IRQF_SHARED, DRIVER, chip);
    if (err < 0)
    {
        snd_printk(KERN_ERR "cannot grab interrupt %d\n", pci->irq);
        err_card
    }
    chip->irq = pci->irq;
    strcpy(card->driver, chip->model.chip);
    strcpy(card->shortname, chip->model.shortname);
    sprintf(card->longname, "%s (rev %u) at %#lx, irq %i", chip->model.longname, chip->revision, chip->addr, chip->irq);
    strcpy(card->mixername, chip->model.chip);
    snd_component_add(card, chip->model.chip);
    err = oxygen_pcm_init(chip);
    if (err < 0)
    {
        err_card
    }
    err = oxygen_mixer_init(chip);
    if (err < 0)
    {
        err_card
    }
    if (chip->model.device_config & (MIDI_OUTPUT | MIDI_INPUT))
    {
        unsigned int info_flags = MPU401_INFO_INTEGRATED;
        if (chip->model.device_config & MIDI_OUTPUT)
        {
            info_flags |= MPU401_INFO_OUTPUT;
        }
        if (chip->model.device_config & MIDI_INPUT)
        {
            info_flags |= MPU401_INFO_INPUT;
        }
        err = snd_mpu401_uart_new(card, 0, MPU401_HW_CMIPCI, chip->addr + OXYGEN_MPU401, info_flags, 0, 0, &chip->midi);
        if (err < 0)
        {
            err_card
        }
    }
    oxygen_proc_init(chip);
    spin_lock_irq(&chip->reg_lock);
    if (chip->model.device_config & CAPTURE_1_FROM_SPDIF)
    {
        chip->interrupt_mask |= OXYGEN_INT_SPDIF_IN_DETECT;
    }
    if (chip->has_ac97_0 | chip->has_ac97_1)
    {
        chip->interrupt_mask |= OXYGEN_INT_AC97;
    }
    oxygen_write16(chip, OXYGEN_INTERRUPT_MASK, chip->interrupt_mask);
    spin_unlock_irq(&chip->reg_lock);
    err = snd_card_register(card);
    if (err < 0)
    {
        err_card
    }
    pci_set_drvdata(pci, card);
    return 0;
    err_pci_regions pci_release_regions(pci);
    err_pci_enable pci_disable_device(pci);
    err_card snd_card_free(card);
    return err;
}