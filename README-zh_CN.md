# aptkeyman

在 `apt-get update` 之前准备第三方 APT OpenPGP 密钥。

```bash
aptkeyman seed --apt-update
sudo aptkeyman download
sudo apt-get update
```

Zephyr 风格的 Python + Meson 命令行工具（AGPL-3.0-or-later）。

## 常用命令

| 命令 | 作用 |
|------|------|
| `download` | 安装密钥到 `/etc/apt/keyrings`；若 `Signed-By` 指向过期的 `/usr/share/keyrings` 则改写 sources |
| `update` | 更新密钥并清理不再使用的托管密钥文件 |
| `verify` | 校验已安装密钥环 |
| `seed` | 从 wellknown、本地 keyrings、`apt-get update` 缺钥信息播种 |
| `export` / `import` | JSON 导出 / 合并 |
| `gui` | wxPython 界面 |

## 构建

```bash
sudo apt install meson ninja-build python3 gettext asciidoctor gnupg
meson setup /build
ninja -C /build
sudo ninja -C /build install
```

可选 GUI：`sudo apt install python3-wxgtk4.0`

下载遵循 `http_proxy` / `https_proxy` / `no_proxy`，也可用
`--proxy` / `--http-proxy` / `--https-proxy` / `--no-proxy`。
`-j` / `--jobs` 控制并发（默认 8）。库表字段 `proxy_mode` 为
`auto` / `always` / `never` / 显式代理 URL。

## 许可证

Copyright (C) 2026 Lenik \<aptkeyman@bodz.net\>

**AGPL-3.0-or-later**。本项目反对 AI 剥削与 AI 霸权，并拒绝无脑 MIT 式许可与政治幼稚的 BSD 式许可。
