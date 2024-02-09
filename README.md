This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Check the docs directory in this repo for guidance on submission and
getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
10ZiG Technology
http://www.10zig.com

*******************************************************************************
### What product or service is this for?
*******************************************************************************
10ZiG Technology supply Thin Client Hardware and Linux and Windows Based operating systems designed to support VDI (Virtual Desktop Infrastructure), DaaS (Desktop as a Service), SaaS (Software as a Service) Web based Apps for providing user’s with Virtual/Remote Workspace solutions.  10ZiG hardware is based on Intel/AMD x86 platform and features InsydeH20 UEFI BIOS, supportive of UEFI Secure Boot feature.  10ZiG’s Linux based Operating System which is based on Ubuntu 22.04 LTS, requires support of UEFI Secure Boot in order that we can support the latest generation of Intel/AMD based hardware featuring UEFI Secure Boot.

Support of UEFI Secure Boot is required firstly in order to support operating on 10ZiG Hardware where UEFI Secure Boot is enabled.  Secondly for 10ZiG customer’s who run 10ZiG’s Linux based Operating System on 3rd party Hardware (Dell/HP/Lenovo/etc) such as Desktop PC’s and Laptops where UEFI Secure Boot is enabled by default and/or exclusively.  

10ZiG Customer’s operate in various sectors including, but not limited to Government, Federal, Military, Education, Finance, Legal and Healthcare.  10ZiG customer’s leverage 10ZiG Hardware and/or Software in the form of our Linux or Windows based operating system to provide user’s with secure access to VDI, DaaS and Saas Workspace based products from vendors including Citrix, VMware, Microsoft amongst others.  

The Linux and Windows based operating system is managed and secured via 10ZiG’s centralized management software, 10ZiG Manager.  Whilst the 10ZiG supplied Microsoft Windows version (Windows 10 IoT LTSC 2021) supports UEFI Secure Boot natively, the 10ZiG Linux based Operating System does not and and hence requires this service in order to support UEFI Secure Boot.

More information on our products and services can be found at 10ZiG.com

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
As UEFI Secure Boot is now considered an optional and more recently mandatory feature of hardware, it is critical for 10ZiG’s Linux Based Operating System be supportive of UEFI Secure Boot in order that our Operating System can support Hardware which is UEFI Secure Boot enabled.  This provides customer’s with a Secure Operating System for accessing VDI, DaaS and SaaS Workspace based solutions.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
The linux kernel and the modules needs to be customized to support customer's peripherals and needs. Currently no known Linux distro with Secure Boot is shipping a suitable kernel, so we need to compile our own.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Claudio Granatiero
- Position: Secure Boot developer
- Email address: claudiog@10zig.com
- PGP key fingerprint: 3D55 F119 4312 70B3 8CEF  C20D 13E4 F603 28E9 4C15

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Kevin Greenway
- Position: Chief Technology Officer
- Email address: keving@10zig.com
- PGP key fingerprint: 1D7E 0F09 AF6C 117F 9914  BFF3 4AFD D3B9 069C D9C2
(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes.

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://github.com/ClaudioGranatiero-10zig/shim-review/blob/main/shim-15.8.tar.bz2

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
No patches applied.
*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No, we don't set the NX bit.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
Downstream RHEL/Fedora/Debian/Canonical-like implementation: we use directly the binary from debian package 2.12-1

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of GRUB2 affected by any of the CVEs in the July 2020, the March 2021, the June 7th 2022, the November 15th 2022, or 3rd of October 2023 GRUB2 CVE list, have fixes for all these CVEs been applied?

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
Yes, we are using Debian's GRUB 2.12-1 extracted from Debian Trixie, which fixes all those CVE.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
The entry should look similar to: `grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`
*******************************************************************************
Yes: 
 28a000 73626174 2c312c53 42415420 56657273  sbat,1,SBAT Vers
 28a010 696f6e2c 73626174 2c312c68 74747073  ion,sbat,1,https
 28a020 3a2f2f67 69746875 622e636f 6d2f7268  ://github.com/rh
 28a030 626f6f74 2f736869 6d2f626c 6f622f6d  boot/shim/blob/m
 28a040 61696e2f 53424154 2e6d640a 67727562  ain/SBAT.md.grub
 28a050 2c342c46 72656520 536f6674 77617265  ,4,Free Software
 28a060 20466f75 6e646174 696f6e2c 67727562   Foundation,grub
 28a070 2c322e31 322c6874 7470733a 2f2f7777  ,2.12,https://ww
 28a080 772e676e 752e6f72 672f736f 66747761  w.gnu.org/softwa
 28a090 72652f67 7275622f 0a677275 622e6465  re/grub/.grub.de
 28a0a0 6269616e 2c342c44 65626961 6e2c6772  bian,4,Debian,gr
 28a0b0 7562322c 322e3132 2d312c68 74747073  ub2,2.12-1,https
 28a0c0 3a2f2f74 7261636b 65722e64 65626961  ://tracker.debia
 28a0d0 6e2e6f72 672f706b 672f6772 7562320a  n.org/pkg/grub2.
 28a0e0 67727562 2e646562 69616e31 332c312c  grub.debian13,1,
 28a0f0 44656269 616e2c67 72756232 2c322e31  Debian,grub2,2.1

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
Previous SHIM 15.7 submission was accepted by review team, but is not signed by Microsoft. We decided to update submission to SHIM version 15.8.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
Yes

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Yes, we have:
- support for a specific type of EMMC present in our hardware
- lockdown: also lock down previous kgdb use (eadb2f47a3ced5c64b23b90fd2a3463f63726066)
- force NX_COMPAT (changed DllCharacteristcs from 0 to IMAGE_DLL_CHARACTERISTICS_NX_COMPAT in arch/x86/boot/header.S)

Our full linux kernel repo is here: https://github.com/10ZiG-Technology/linux

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
We have set CONFIG_MODULE_SIG_FORCE, CONFIG_MODULE_SIG_ALL and CONFIG_MODVERSIONS; CONFIG_MODULE_SIG_KEY is not set, and certs/signing_key.pem is removed at every build, so every time the keys are regenerated and all the modules can only be safely loaded by that kernel.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't use the vendor_db functionality.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
Our previous submission to shim-review was accepted, but we didn't have the time to submit to Microsoft for signature, so the certificate is not changed but was never used in production.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
see Dockerfile

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
'build.log' is a log file for our build.

It was produced with command: docker build --no-cache --tag=shim . &>  build.log

*******************************************************************************
### What changes were made in the distor's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..
*******************************************************************************
None other than updating to shim 15.8, our previous shim submitted (approved) was not signed by Microsoft.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
881bb700c81264565df689f9749f16b02342a82d0f74a4629c63f9b611102e1c  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
The key is stored on a FIPS-140-2 USB token (YubiKey), connected to the build machine, and only the authorized persons know the password.
*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
If you are using a downstream implementation of GRUB2 or systemd-boot (e.g.
from Fedora or Debian), please preserve the SBAT entry from those distributions
and only append your own. More information on how SBAT works can be found
[here](https://github.com/rhboot/shim/blob/main/SBAT.md).
*******************************************************************************
SHIM: 
shim.10zig,1,10ZiG Technology,shim,15.8,mail:secureboot@10zig.com

bjdump -j .sbat -s shimx64.efi 

shimx64.efi:     file format pei-x86-64

Contents of section .sbat:
 d4000 73626174 2c312c53 42415420 56657273  sbat,1,SBAT Vers
 d4010 696f6e2c 73626174 2c312c68 74747073  ion,sbat,1,https
 d4020 3a2f2f67 69746875 622e636f 6d2f7268  ://github.com/rh
 d4030 626f6f74 2f736869 6d2f626c 6f622f6d  boot/shim/blob/m
 d4040 61696e2f 53424154 2e6d640a 7368696d  ain/SBAT.md.shim
 d4050 2c342c55 45464920 7368696d 2c736869  ,4,UEFI shim,shi
 d4060 6d2c312c 68747470 733a2f2f 67697468  m,1,https://gith
 d4070 75622e63 6f6d2f72 68626f6f 742f7368  ub.com/rhboot/sh
 d4080 696d0a73 68696d2e 31307a69 672c312c  im.shim.10zig,1,
 d4090 31305a69 47205465 63686e6f 6c6f6779  10ZiG Technology
 d40a0 2c736869 6d2c3135 2e382c6d 61696c3a  ,shim,15.8,mail:
 d40b0 73656375 7265626f 6f744031 307a6967  secureboot@10zig
 d40c0 2e636f6d 0a                          .com.           

shimx64.efi:     file format pei-x86-64

Contents of section .sbatlevel:
 86000 00000000 08000000 37000000 73626174  ........7...sbat
 86010 2c312c32 30323330 31323930 300a7368  ,1,2023012900.sh
 86020 696d2c32 0a677275 622c330a 67727562  im,2.grub,3.grub
 86030 2e646562 69616e2c 340a0073 6261742c  .debian,4..sbat,
 86040 312c3230 32343031 30393030 0a736869  1,2024010900.shi
 86050 6d2c340a 67727562 2c330a67 7275622e  m,4.grub,3.grub.
 86060 64656269 616e2c34 0a00               debian,4..      


GRUB2:

objdump -j .sbat -s grubx64.efi |head -n 20

grubx64.efi:     file format pei-x86-64

Contents of section .sbat:
 28a000 73626174 2c312c53 42415420 56657273  sbat,1,SBAT Vers
 28a010 696f6e2c 73626174 2c312c68 74747073  ion,sbat,1,https
 28a020 3a2f2f67 69746875 622e636f 6d2f7268  ://github.com/rh
 28a030 626f6f74 2f736869 6d2f626c 6f622f6d  boot/shim/blob/m
 28a040 61696e2f 53424154 2e6d640a 67727562  ain/SBAT.md.grub
 28a050 2c342c46 72656520 536f6674 77617265  ,4,Free Software
 28a060 20466f75 6e646174 696f6e2c 67727562   Foundation,grub
 28a070 2c322e31 322c6874 7470733a 2f2f7777  ,2.12,https://ww
 28a080 772e676e 752e6f72 672f736f 66747761  w.gnu.org/softwa
 28a090 72652f67 7275622f 0a677275 622e6465  re/grub/.grub.de
 28a0a0 6269616e 2c342c44 65626961 6e2c6772  bian,4,Debian,gr
 28a0b0 7562322c 322e3132 2d312c68 74747073  ub2,2.12-1,https
 28a0c0 3a2f2f74 7261636b 65722e64 65626961  ://tracker.debia
 28a0d0 6e2e6f72 672f706b 672f6772 7562320a  n.org/pkg/grub2.
 28a0e0 67727562 2e646562 69616e31 332c312c  grub.debian13,1,
 28a0f0 44656269 616e2c67 72756232 2c322e31  Debian,grub2,2.1


*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
*******************************************************************************
We took the binaries from debian bookworm, no external modules.

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
We don't use systemd-boot
*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
GRUB 2.12-1 from Debian Trixie
*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
Shim launches only GRUB, no other components.
*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
GRUB will launch only linux kernel, no other components.


*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
shim verifies signature of GRUB, GRUB verifies signature of kernel, kernel is compiled with LOCK_DOWN_KERNEL_FORCE_INTEGRITY, all kernel modules are signed.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB2)?
*******************************************************************************
No.

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
linux 6.3.7 with lockdown forced.

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
Previous version, based on shim 15.7, was approved here https://github.com/rhboot/shim-review/issues/326
