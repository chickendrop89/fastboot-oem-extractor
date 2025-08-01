# fastboot-oem-extractor 
Extract hidden "fastboot oem" commands from firmware blobs

## Supported firmware
These firmware blobs will be accepted by this tool 
- `ABL` (Qualcomm)
- `LK1st, LK2nd` (Qualcomm)
- `LK` (MediaTek)
- `FBPK` Containers (Google)
- `DHTB` Signed binaries (U-Boot)
- Anything else containing UEFI PEs

This is an artificial barrier for when this tool is ran in a loop against firmware images

## How to use:
1. Install python requirements
```shell
pip install -r requirements.txt
```

2. Prepare your firmware images from the internet, or by pulling them off the device with `adb`
3. Run extractor.py against the image
```shell
╰─$ ./extractor.py abl.img
(x) Reading firmware file: abl.img
(x) Found valid firmware structure at offset: 0x3000
(x) Extracting firmware...
(x) Found 1 UEFI portable executable(s)
(x) Matching 'oem *' ascii strings

oem device-info
oem disable-charger-screen
oem edl
oem enable-charger-screen
oem erase-vb-index
oem fbreason
oem getguid
oem getlog
oem lkmsg
oem lock
oem lpmsg
oem off-mode-charge
oem poweroff
oem select-display-panel
oem set-hw-fence-value
oem uart-enable
oem unlock
```

If your file is some sparse image that does not contain any UEFI PEs or common binary magic bytes,
you can force the string lookup via this command line option:
```shell
--force-string-lookup
```

## Disclaimer:
In rare cases, this code might output some hallucinations of commands that don't exist,
or don't work after the device is sent out of factory. Keep this in mind
