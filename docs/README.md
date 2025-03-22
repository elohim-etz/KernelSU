# KernelSU

<img src="https://kernelsu.org/logo.png" style="width: 96px;" alt="logo">

> **This is an unofficial fork, all rights reserved [@tiann](https://github.com/tiann).**

---

## Execute the following command in the root directory of the kernel source code:

```bash
curl -LSs "https://raw.githubusercontent.com/elohim-etz/KernelSU/12071+sus/kernel/setup.sh" | bash -s
```

## Features

1. Kernel-based `su` and root access management.
2. Module system based on [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS).
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Lock up the root power in a cage.

## Compatibility state

KernelSU officially supports Android GKI 2.0 devices (kernel 5.10+). Older kernels (4.14+) are also supported, but the kernel will need to be built manually.

With this, WSA, ChromeOS, and container-based Android are all supported.

Currently, only the `arm64-v8a` and `x86_64` architectures are supported.

## Usage

- [Installation](https://kernelsu.org/guide/installation.html)
- [How to build](https://kernelsu.org/guide/how-to-build.html)
- [Official website](https://kernelsu.org/)

## Translation

To help translate KernelSU or improve existing translations, please use [Weblate](https://hosted.weblate.org/engage/kernelsu/). PR of Manager's translation is no longer accepted, because it will conflict with Weblate.

## Discussion

- Telegram: [@KernelSU](https://t.me/KernelSU)

## Security

For information on reporting security vulnerabilities in KernelSU, see [SECURITY.md](/SECURITY.md).

## License

- Files under the `kernel` directory are [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts except the `kernel` directory are [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## Credits

- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): The KernelSU idea.
- [Magisk](https://github.com/topjohnwu/Magisk): The powerful root tool.
- [genuine](https://github.com/brevent/genuine/): APK v2 signature validation.
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some rootkit skills.

```

```
