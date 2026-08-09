# AdGuard Balanced List

面向手机 AdGuard Home 的轻量均衡合并规则：

- OISD Small：主规则
- AWAvenue：中文 App 广告补充
- URLHaus：恶意域名补充

每天由 GitHub Actions 自动下载、规范化、去重并更新。

## 订阅地址

```text
https://raw.githubusercontent.com/OWNER/adguard-balanced-list/main/dist/adguard-balanced.txt
```

仓库创建后，请将 `OWNER` 替换为实际 GitHub 用户名。

## 去重逻辑

- 识别 AdGuard/Adblock `||domain^` 规则；
- 识别 Hosts、纯域名和常见 dnsmasq 域名格式；
- 域名统一转为小写并去除尾部点；
- 精确域名去重，并删除已被父域规则覆盖的子域规则；
- 无法安全规范化的有效高级规则按原样保留并精确去重；
- 任一上游下载失败时整次构建失败，避免发布残缺列表；
- 如果规则数量异常过少，拒绝覆盖已有输出。

## 本地生成

```bash
python3 scripts/merge_rules.py
python3 -m unittest discover -s tests -v
```

## 输出

- `dist/adguard-balanced.txt`：可直接添加到 AdGuard Home DNS 封锁清单；
- `dist/stats.json`：构建统计信息。

## License

本仓库代码采用 MIT License。合并输出中的规则仍分别受各上游项目许可和条款约束。
