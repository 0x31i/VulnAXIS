# OC-AXIS
Automate the setup of a vulnerable AXIS security camera.

```bash
# change directory to where the script has been saved
cd scripts

# "Cat" the script in the terminal send the output to the /tmp folder on the AXIS camera
cat vulnaxis.sh | ssh root@192.168.1.132 "cat › /tmp/vulnaxis.sh"

*****★★★★★★★*********★*★*★************★
* AXIS Camera SSH Service
* Firmware: 10.5.0
Places
* Device ID: ********
★★★★★★★★★★★★★★★*★★★★★★★★★★*★★★★★★★★★★★★

root@192.168.1.132's password:


# SSH into the AXIS camera
ssh root@192.168.1.132

★★★★*★★★★★★★★★★★★★★★★★★★★★★★★★★
* AXIS Camera SSH Service
* Firmware: 10.5.0
* Device ID: ********
*******************************

root@192.168.1.132's password:

[root@axis-accc8e0c3f70 /mnt/flash/root]2008# ls
suid_flag

# Change directory into the /tmp folder (where the script was saved)
[root@axis-accc8e0c3f70 /mnt/flash/root]2008# cd /tmp/

[root@axis-accc8e0c3f70 /tmp]2008# ls
vulnaxis.sh

# Make the script executable
[root@axis-accc8e0c3f70 /tmp]2008# chmod +x vulnaxis.sh

# Execute the script
[root@axis-accc8e0c3f70 /tmp]2008# sh vulnaxis.sh
```
