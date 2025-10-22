static s32 dpot_write_spi(struct dpot_data *dpot, u8 reg, u16 value)
{
    unsigned val = 0;
    if (!(reg & (DPOT_ADDR_EEPROM | DPOT_ADDR_CMD | DPOT_ADDR_OTP)))
    {
        if (dpot->feat & F_RDACS_WONLY)
        {
            dpot->rdac_cache[reg & DPOT_RDAC_MASK] = value;
        }
        if (dpot->feat & F_AD_APPDATA)
        {
            if (dpot->feat & F_SPI_8BIT)
            {
                val = ((reg & DPOT_RDAC_MASK) << DPOT_MAX_POS(dpot->devid)) | value;
                return dpot_write_d8(dpot, val);
            }
            if (dpot->feat & F_SPI_16BIT)
            {
                val = ((reg & DPOT_RDAC_MASK) << DPOT_MAX_POS(dpot->devid)) | value;
                return dpot_write_r8d8(dpot, val >> 8, val & 0xFF);
            }
            else
            {
                BUG();
            }
        }
        else
        {
            if (dpot->uid == DPOT_UID(AD5291_ID) || dpot->uid == DPOT_UID(AD5292_ID) || dpot->uid == DPOT_UID(AD5293_ID))
            {
                dpot_write_r8d8(dpot, DPOT_AD5291_CTRLREG << 2, DPOT_AD5291_UNLOCK_CMD);
                if (dpot->uid == DPOT_UID(AD5291_ID))
                {
                    value = value << 2;
                }
                return dpot_write_r8d8(dpot, (DPOT_AD5291_RDAC << 2) | (value >> 8), value & 0xFF);
            }
            if (dpot->uid == DPOT_UID(AD5270_ID) || dpot->uid == DPOT_UID(AD5271_ID))
            {
                dpot_write_r8d8(dpot, DPOT_AD5270_1_2_4_CTRLREG << 2, DPOT_AD5270_1_2_4_UNLOCK_CMD);
                if (dpot->uid == DPOT_UID(AD5271_ID))
                {
                    value = value << 2;
                }
                return dpot_write_r8d8(dpot, (DPOT_AD5270_1_2_4_RDAC << 2) | (value >> 8), value & 0xFF);
            }
            val = DPOT_SPI_RDAC | (reg & DPOT_RDAC_MASK);
        }
    }
    if (reg & DPOT_ADDR_EEPROM)
    {
        val = DPOT_SPI_EEPROM | (reg & DPOT_RDAC_MASK);
    }
    if (reg & DPOT_ADDR_CMD)
    {
        switch (reg)
        {
        case DPOT_DEC_ALL_6DB:
            val = DPOT_SPI_DEC_ALL_6DB;
            break;
        case DPOT_INC_ALL_6DB:
            val = DPOT_SPI_INC_ALL_6DB;
            break;
        case DPOT_DEC_ALL:
            val = DPOT_SPI_DEC_ALL;
            break;
        case DPOT_INC_ALL:
            val = DPOT_SPI_INC_ALL;
            break;
        }
    }
    if (reg & DPOT_ADDR_OTP)
    {
        if (dpot->uid == DPOT_UID(AD5291_ID) || dpot->uid == DPOT_UID(AD5292_ID))
        {
            return dpot_write_r8d8(dpot, DPOT_AD5291_STORE_XTPM << 2, 0);
        }
        if (dpot->uid == DPOT_UID(AD5270_ID) || dpot->uid == DPOT_UID(AD5271_ID))
        {
            return dpot_write_r8d8(dpot, DPOT_AD5270_1_2_4_STORE_XTPM << 2, 0);
        }
    }
    else
    {
        BUG();
    }
    if (dpot->feat & F_SPI_16BIT)
    {
        return dpot_write_r8d8(dpot, val, value);
    }
    if (dpot->feat & F_SPI_24BIT)
    {
        return dpot_write_r8d16(dpot, val, value);
    }
    return -EFAULT;
}