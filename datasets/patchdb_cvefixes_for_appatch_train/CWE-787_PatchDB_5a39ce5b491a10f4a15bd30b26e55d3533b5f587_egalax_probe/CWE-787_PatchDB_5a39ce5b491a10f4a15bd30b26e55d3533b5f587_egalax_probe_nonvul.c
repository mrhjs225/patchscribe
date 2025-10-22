static int egalax_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
    int ret;
    struct egalax_data *td;
    struct hid_report *report;
    td = kzalloc(sizeof(egalax_data), GFP_KERNEL);
    if (!td)
    {
        dev_err(&hdev->dev, "cannot allocate eGalax data\n");
        return -ENOMEM;
    }
    hid_set_drvdata(hdev, td);
    ret = hid_parse(hdev);
    if (ret)
    {
        end
    }
    ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
    if (ret)
    {
        end
    }
    report = hdev->report_enum[HID_FEATURE_REPORT].report_id_hash[5];
    if (report)
    {
        report->field[0]->value[0] = 2;
        usbhid_submit_report(hdev, report, USB_DIR_OUT);
    }
    end if (ret) { kfree(td); }
    return ret;
}