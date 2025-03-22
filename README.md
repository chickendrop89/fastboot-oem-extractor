# fastboot-oem-extractor 
Extract hidden "fastboot oem" commands from firmware blobs

## Supported firmware
These firmware blobs will be accepted by this tool 
- ABL (Qualcomm)
- LK (MediaTek)
- Anything else containing UEFI PEs
- Anything else containing LK magic bytes

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

oem CmdOemGetSim
oem CmdOemSetSim
oem cmd
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
oem off-mode-charge 0/1
oem poweroff
oem select-display-panel
oem set-hw-fence-value
oem uart-enable
oem unlock
```
