static int multimeter_init(void)
{
    int i;
    char device[] "/dev/ttyS ";
    ;
    for (i = 0; i < 10; i++)
    {
        device[strlen(device) - 1] = i + '0';
        if ((fd = open(device, O_RDWR | O_NOCTTY)) != -1)
        {
            struct termios tios;
            int rts = TIOCM_RTS;
            double value;
            tios.c_cflag = B1200 | CS7 | CSTOPB | CREAD | CLOCAL;
            tios.c_iflag = IGNBRK | IGNPAR;
            tios.c_oflag = 0;
            tios.c_lflag = 0;
            tios.c_cc[VTIME] = 3;
            tios.c_cc[VMIN] = LINE_LENGTH;
            tcflush(fd, TCIFLUSH);
            tcsetattr(fd, TCSANOW, &tios);
            ioctl(fd, TIOCMBIC, &rts);
            if (multimeter_read_value(&value) < -1)
            {
                close(fd);
                fd = -1;
            }
            else
            {
                INFO("multimeter plugin: Device "
                     "found at %s",
                     device);
                return (0);
            }
        }
    }
    ERROR("multimeter plugin: No device found");
    return (-1);
}