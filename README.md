# nxpflash
Download progress:
1. Boot up from serial downloding
2. Download accessory boot loader
3. operation:Download image to flash


NXP serial download mode command:
1. get status, cmd 0x05 0x05
  0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
2. write file, cmd 0x04, 0x04, 

cmd | address | zero | size | zero 
----| ------- | ---- | ---- | ----
0x04, 0x04, |  0x00, 0x00, 0x00, 0x00, | 0x00, |	0x00, 0x00, 0x00, 0x00, |	0x00, 0x00, 0x00, 0x00, 0x00

3. Jump address, cmd 0x0B, 0x0B, 

cmd | address | zero 
----| ------- | ---- 
0x0B, 0x0B, |  0x00, 0x00, 0x00, 0x00, | 0x00, 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

the jump address should have a IVT table
