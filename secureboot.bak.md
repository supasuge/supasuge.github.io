---
author: supaaasuge
title: How to setup Secure Boot on Arch Linux
date: 2024-05-11
lastmod: 2024-05-11
description: Short writeup on how to setup secure boot on arch linux.
categories:
  - Arch Linux
tags:
  - Arch Linux
  - Based Distro 
---

# What is Secure Boot?
Secure Boot is a feature of UEFI firmware's that increase the security of the system by booting only trusted components (such as bootloaders and kernels that have been cryptographically signed and marked as trusted). By default, Arch Linux and many other linux distributions do not have secure boot support by default apart from Ubuntu and a few other mainstream Linux distributions.

## What is a "Trusted" component?
A trusted component is a physical piece of hardware that has been cryptographically signed using the private key of an Asymmetric key pair, typically RSA-2048. The public part needs to be loaded into the firmware database of trusted keys.

Every UEFI Secure Boot implementation starts with the Platform Key, this is the most important key. The platform key is used as the root of trust chains. Secure Boot cannot be enabled unless a Platform Key has been enrolled and there is usually only one PK. Platform keys are not used to directy sign boot components, instead they are used to disable Secure Boot, and sign Key Exchange Keys.

### Quick Note on UEFI
- [Source](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface)
The **Unified Extensible Firmware Intergace** is an interface between operating systems and firmware. It provides a standard environment for booting an operating system and running pre-boot applications. It's distinct from the "MBR boot code" method that was used by legacy BIOS systems. The UEFI specification defines several key stores and their formats: The Platform Key(PK), The Key Exchange Key(KEK), the key database (db), and the forbidden signatures database (dbx).

### Getting started setting up Secure Boot on an existing Arch Installation
First things first, let's go ahead and download the necessary packages using `pacman`:
```bash
sudo pacman -S sbctl dracut sbsigntools
```
- `sbctl`: Used to create keys for secure boot, and securely enroll them and keep track of files to sign.
- `dracut`: Creates an initial image used by the kernel for preloading the block device modules (IDE, SCSI, or RAID) which are needed to access the root filesystem.


#### Scripts + packages needed
- [Source](https://github.com/Ataraxxia/secure-arch/blob/main/00_basic_system_installation.md)
Make sure to create the following scripts below that will hook into `pacman`:
`/usr/local/bin/dracut-install.sh` - Dracut install
```bash
#!/bin/bash

mkdir -p /boot/efi/EFI/Linux

while read -r line; do
	if [[ "$line" == 'usr/lib/modules/'+([^/])'/pkgbase' ]]; then
		kver="${line#'usr/lib/modules/'}"
		kver="${kver%'/pkgbase'}"
	
		dracut --force --uefi --kver "$kver" /boot/efi/EFI/Linux/arch-linux.efi
	fi
done
```

And for the removal script:
`/usr/local/bin/dracut-remove.sh`
```bash
#!/bin/bash
rm -f /boot/efi/EFI/Linux/arch-linux.efi
```

Next, make the scripts executable and create pacman's hook directory:
```bash
chmod +x /usr/local/bin/dracut-*
mkdir /etc/pacman.d/hooks
```

Now, for the actual hooks... First for the installation/upgrade:
`/etc/pacman.d/hooks/90-dracut-install.hook`
```bash
[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Target = usr/lib/modules/*/pkgbase
	
[Action]
Description = Updating linux EFI image
When = PostTransaction
Exec = /usr/local/bin/dracut-install.sh
Depends = dracut
NeedsTargets
```

And, for the removal:
`/etc/pacman.d/hooks/60-dracut-remove.hook`
```bash
[Trigger]
Type = Path
Operation = Remove
Target = usr/lib/modules/*/pkgbase
	
[Action]
Description = Removing linux EFI image
When = PreTransaction
Exec = /usr/local/bin/dracut-remove.sh
NeedsTargets
```
*To be continue...*

#### Setting up Secure Boot
At this point, make sure to reboot your computer and boot to the BIOS settings screen. The button to push to access this screen is different for most computers, a quick google search or trial and error is needed if you are unsure. Once you access the BIOS settings, you should then enable Setup Mode in the SecureBoot settings, and erase your existing keys.

With Setup Mode enabled, we can start configuring our Secure Boot installation with Grub as our bootloader:

1. Creating and enrolling keys
```bash
sbctl status # Verify the secure boot status (should denote that it's in setup mode)
sbctl create-keys # This creates yours keys
```
2. Check the status again & files that need to be signed for secure boot to work
```bash
sbctl status # sbctl should be installed now
sbctl verify # Check what files need to be signed
```
3. Sign necessary boot files with the keys you just created. Usually just the kernel and bootloader need to be signed
```bash
sbctl sign -s /path/to/kernel/bootloader.efi
```
4. Let dracut know to sign it's unified kernel images when it creates them:
- Create the following file: `/etc/dracut.conf.d/secureboot.conf`
```bash
uefi_secureboot_cert="/usr/share/secureboot/keys/db/db.pem"
uefi_secureboot_key="/usr/share/secureboot/keys/db/db.key"
```
5. Finally, enroll the keys
Note that `-m` also enroll's Microsoft keys. Some hardware needs microsoft keys sometimes for secure boot to work properly, so only drop the `-m` if you know what your doing.
```bash
sbctl enroll-keys -m
```
6. Reboot you system, and enable secure boot in your BIOS firmware settings.
7. Enjoy!


###### Resources
- https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot
- https://man.archlinux.org/man/extra/sbctl/sbctl.8.en
- https://wiki.archlinux.org/title/User:Krin/Secure_Boot,_full_disk_encryption,_and_TPM2_unlocking_install
- https://github.com/Ataraxxia/secure-arch/blob/main/00_basic_system_installation.md
- https://wiki.archlinux.org/title/Dracut