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
[unchanged]

10ZiG Technology

http://www.10zig.com

*******************************************************************************
### What's the legal data that proves the organization's genuineness?
The reviewers should be able to easily verify, that your organization is a legal entity, to prevent abuse.
Provide the information, which can prove the genuineness with certainty.
*******************************************************************************
Company/tax register entries or equivalent:
(a link to the organization entry in your jurisdiction's register will do)

[new]

10ZiG Technology Inc

Nevada Business Identification # NV20031241651

Can be verified at https://www.nvsilverflume.gov/home


The public details of both your organization and the issuer in the EV certificate used for signing .cab files at Microsoft Hardware Dev Center File Signing Services.
(**not** the CA certificate embedded in your shim binary)

Example:

```
Issuer: O=MyIssuer, Ltd., CN=MyIssuer EV Code Signing CA
Subject: C=XX, O=MyCompany, Inc., CN=MyCompany, Inc.
```

[new]

Serial number: 00 8D 8D B4 D7 E3 EE B4 51 B4 A8 3C 77 A5 24 C6 20

Issued to: 10ZiG Technology Inc

Issued by: Sectigo Public Code Signing CA EV R36

Valid from: 6-Jun-2025

Valid to: 5-Jun-2028

Intended purposes: Code Signing

Friendly name: <None>

State: Valid

*******************************************************************************
### What product or service is this for?
*******************************************************************************
[unchanged]

10ZiG Technology supply Thin Client Hardware and Linux and Windows Based operating systems designed to support VDI (Virtual Desktop Infrastructure), DaaS (Desktop as a Service), SaaS (Software as a Service) Web based Apps for providing user’s with Virtual/Remote Workspace solutions.  10ZiG hardware is based on Intel/AMD x86 platform and features InsydeH20 UEFI BIOS, supportive of UEFI Secure Boot feature.  10ZiG’s Linux based Operating System which is based on Ubuntu 22.04 LTS, requires support of UEFI Secure Boot in order that we can support the latest generation of Intel/AMD based hardware featuring UEFI Secure Boot.

Support of UEFI Secure Boot is required firstly in order to support operating on 10ZiG Hardware where UEFI Secure Boot is enabled.  Secondly for 10ZiG customer’s who run 10ZiG’s Linux based Operating System on 3rd party Hardware (Dell/HP/Lenovo/etc) such as Desktop PC’s and Laptops where UEFI Secure Boot is enabled by default and/or exclusively.  

10ZiG Customer’s operate in various sectors including, but not limited to Government, Federal, Military, Education, Finance, Legal and Healthcare.  10ZiG customer’s leverage 10ZiG Hardware and/or Software in the form of our Linux or Windows based operating system to provide user’s with secure access to VDI, DaaS and Saas Workspace based products from vendors including Citrix, VMware, Microsoft amongst others.  

The Linux and Windows based operating system is managed and secured via 10ZiG’s centralized management software, 10ZiG Manager.  Whilst the 10ZiG supplied Microsoft Windows version (Windows 10 IoT LTSC 2021) supports UEFI Secure Boot natively, the 10ZiG Linux based Operating System does not and and hence requires this service in order to support UEFI Secure Boot.

More information on our products and services can be found at 10ZiG.com

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
[unchanged]

As UEFI Secure Boot is now considered an optional and more recently mandatory feature of hardware, it is critical for 10ZiG’s Linux Based Operating System be supportive of UEFI Secure Boot in order that our Operating System can support Hardware which is UEFI Secure Boot enabled.  This provides customer’s with a Secure Operating System for accessing VDI, DaaS and SaaS Workspace based solutions.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
[unchanged]

The linux kernel and the modules needs to be customized to support customer's peripherals and needs. Currently no known Linux distro with Secure Boot is shipping a suitable kernel, so we need to compile our own.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
[unchanged]

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
[unchanged]

- Name: Kevin Greenway
- Position: Chief Technology Officer
- Email address: keving@10zig.com
- PGP key fingerprint: 1D7E 0F09 AF6C 117F 9914  BFF3 4AFD D3B9 069C D9C2
(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 16.0 shim release tar?
Please create your shim binaries starting with the 16.0 shim release tar file: https://github.com/rhboot/shim/releases/download/16.0/shim-16.0.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/16.0 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum with the following ones:

```
7b518edd63eb840081912f095ed1487a  shim-16.0.tar.bz2
c2453b9b3c02bc01eea248e9cf634a179ff8828c  shim-16.0.tar.bz2
d503f778dc75895d3130da07e2ff23d2393862f95b6cd3d24b10cbd4af847217  shim-16.0.tar.bz2
b4367f3b1e0716d093f4230902e392d3228bd346e2e07a9377c498d8b3b08a5c0ad25c31aa03af66f54648618074a29b55a3e51925e5cfe5c7ac97257bd25880  shim-16.0.tar.bz2
```

Make sure that you've verified that your build process uses that file
as a source of truth (excluding external patches) and its checksum
matches. You can also further validate the release by checking the PGP
signature: there's [a detached
signature](https://github.com/rhboot/shim/releases/download/16.0/shim-16.0.tar.bz2.asc)

The release is signed by the maintainer Peter Jones - his master key
has the fingerprint `B00B48BC731AA8840FED9FB0EED266B70F4FEF10` and the
signing sub-key in the signature here has the fingerprint
`02093E0D19DDE0F7DFFBB53C1FD3F540256A1372`. A copy of his public key
is included here for reference:
[pjones.asc](https://github.com/rhboot/shim-review/pjones.asc)

Once you're sure that the tarball you are using is correct and
authentic, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
Yes.

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************
https://github.com/ClaudioGranatiero-10zig/shim-review/blob/10zig-shim-x64-20250624/shim-16.0.tar.bz2

*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************
[unchanged]

No patches applied.
*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
[unchanged]

No, we don't set the NX bit.

*******************************************************************************
### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
Skip this, if you're not using GRUB2.
*******************************************************************************
[unchanged]

Downstream RHEL/Fedora/Debian/Canonical-like implementation: we use directly the binary from debian package 2.12-1

*******************************************************************************
### Do you have fixes for all the following GRUB2 CVEs applied?
**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

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
[unchanged]

Yes, we are using Debian's GRUB 2.12-1 extracted from Debian Trixie, which fixes all those CVE.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:  
`grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************
[unchanged]

Yes: 
```
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
```

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************
[updated]

Previous SHIM 15.8 submission was accepted by review team and signed by Microsoft. We decided to update submission to SHIM version 16.0. The GRUB2 binary loaded by new shim is unchanged.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.  
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
[unchanged]

Yes

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
[unchanged]

Yes, we have:
- support for a specific type of EMMC present in our hardware
- lockdown: also lock down previous kgdb use (eadb2f47a3ced5c64b23b90fd2a3463f63726066)
- force NX_COMPAT (changed DllCharacteristcs from 0 to IMAGE_DLL_CHARACTERISTICS_NX_COMPAT in arch/x86/boot/header.S)

Our full linux kernel repo is here: https://github.com/10ZiG-Technology/linux

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
[unchanged]

We have set CONFIG_MODULE_SIG_FORCE, CONFIG_MODULE_SIG_ALL and CONFIG_MODVERSIONS; CONFIG_MODULE_SIG_KEY is not set, and certs/signing_key.pem is removed at every build, so every time the keys are regenerated and all the modules can only be safely loaded by that kernel.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
[unchanged]

We don't use the vendor_db functionality.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
[new]

Our current implementation of shim 15.8 is already not exposed to the mentioned CVEs. We are simply updating the shim to version 16.0 and let Microsoft sign it (hopefully) with the new UEFI CA 2023. When Microsoft would revoke its old UEFI CA 2011, our current shim would be automatically rejected.

*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************
[unchanged]

see Dockerfile

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
[unchanged]

'build.log' is a log file for our build.

It was produced with command: docker build --no-cache --tag=shim . &>  build.log

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..
Skip this, if this is your first application for having shim signed.
*******************************************************************************
[new]

None other than updating to shim 16.0.

*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************
6c9a771fed2df585e41e37ecaa3430a77d234156d77c6b741ec7b1ea16f78d7d

*******************************************************************************
### How do you manage and protect the keys used in your shim?
Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.
*******************************************************************************
[unchanged]

The key is stored on a FIPS-140-2 USB token (YubiKey), connected to the build machine, and only the authorized persons know the password.
*******************************************************************************
### Do you use EV certificates as embedded certificates in the shim?
A _yes_ or _no_ will do. There's no penalty for the latter.
*******************************************************************************
[unchanged]

No.

*******************************************************************************
### Are you embedding a CA certificate in your shim?
A _yes_ or _no_ will do. There's no penalty for the latter. However,
if _yes_: does that certificate include the X509v3 Basic Constraints
to say that it is a CA? See the [docs](./docs/) for more guidance
about this.
*******************************************************************************
[new]

Yes, and yes, it includes the CA constraint

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
```
shim.10zig,1,10ZiG Technology,shim,16.0,mail:secureboot@10zig.com

bjdump -j .sbat -s shimx64.efi 

shimx64.efi:     file format pei-x86-64

Contents of section .sbat:
 dd000 73626174 2c312c53 42415420 56657273  sbat,1,SBAT Vers
 dd010 696f6e2c 73626174 2c312c68 74747073  ion,sbat,1,https
 dd020 3a2f2f67 69746875 622e636f 6d2f7268  ://github.com/rh
 dd030 626f6f74 2f736869 6d2f626c 6f622f6d  boot/shim/blob/m
 dd040 61696e2f 53424154 2e6d640a 7368696d  ain/SBAT.md.shim
 dd050 2c342c55 45464920 7368696d 2c736869  ,4,UEFI shim,shi
 dd060 6d2c312c 68747470 733a2f2f 67697468  m,1,https://gith
 dd070 75622e63 6f6d2f72 68626f6f 742f7368  ub.com/rhboot/sh
 dd080 696d0a73 68696d2e 31307a69 672c312c  im.shim.10zig,1,
 dd090 31305a69 47205465 63686e6f 6c6f6779  10ZiG Technology
 dd0a0 2c736869 6d2c3136 2e302c6d 61696c3a  ,shim,16.0,mail:
 dd0b0 73656375 7265626f 6f744031 307a6967  secureboot@10zig
 dd0c0 2e636f6d 0a                          .com.           

shimx64.efi:     file format pei-x86-64

Contents of section .sbatlevel:
 8d000 00000000 08000000 38000000 73626174  ........8...sbat
 8d010 2c312c32 30323430 34303930 300a7368  ,1,2024040900.sh
 8d020 696d2c34 0a677275 622c340a 67727562  im,4.grub,4.grub
 8d030 2e706569 6d616765 2c320a00 73626174  .peimage,2..sbat
 8d040 2c312c32 30323530 32313830 300a7368  ,1,2025021800.sh
 8d050 696d2c34 0a677275 622c350a 00        im,4.grub,5..   
```

```

GRUB2:
```
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
```

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************
[Unchanged]

We took the binaries from debian bookworm, no external modules.

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
[Unchanged]

We don't use systemd-boot

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
[Unchanged]

GRUB 2.12-1 from Debian Trixie

*******************************************************************************
### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.
Hint: The most common case here will be a firmware updater like fwupd.
*******************************************************************************
[Unchanged]

Shim launches only GRUB, no other components.
*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
[Unchanged]

GRUB will launch only linux kernel, no other components.


*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
Summarize in one or two sentences, how your secure bootchain works on higher level.
*******************************************************************************
[Unchanged]

shim verifies signature of GRUB, GRUB verifies signature of kernel, kernel is compiled with LOCK_DOWN_KERNEL_FORCE_INTEGRITY, all kernel modules are signed.

*******************************************************************************
### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?
*******************************************************************************
[New]

If Secure Boot is disabled, GRUB2 can load an unsigned kernel (checking the builtin "lockdown" variable)

*******************************************************************************
### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?
*******************************************************************************
[Unchanged]

linux 6.3.7 with lockdown forced.

*******************************************************************************
### What contributions have you made to help us review the applications of other applicants?
The reviewing process is meant to be a peer-review effort and the best way to have your application reviewed faster is to help with reviewing others. We are in most cases volunteers working on this venue in our free time, rather than being employed and paid to review the applications during our business hours. 

A reasonable timeframe of waiting for a review can reach 2-3 months. Helping us is the best way to shorten this period. The more help we get, the faster and the smoother things will go.

For newcomers, the applications labeled as [*easy to review*](https://github.com/rhboot/shim-review/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+to+review%22) are recommended to start the contribution process.
*******************************************************************************
[New]

During our previous submission I've tried to help with some peer reviews on the queue. Now that we are back in line, I hope to be helpful again.

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
Previous version, based on shim 15.8, was approved here https://github.com/rhboot/shim-review/issues/376
