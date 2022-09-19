# README.md

## 機能概要

WORDPRESS の脆弱性 TSV 形式でリスト化します。

## 前提事項

* MainWP プラグインのデータベースを使用するため、MainWP に WORDPRESS が登録されていること

> https://mainwp.com/

## 定期実行

スクリプトを実行するサーバで、次のように CRON の登録を行います。

```
0 12 * * * /bin/bash /home/kusanagi/wpscan/wpscan.sh > /var/log/wpscan/wpscan.log
```

## ログローテーション

スクリプトを実行するサーバで、次のようにログローテーションの登録を行います。

```
sudo cp logrotate.d/wpscan /etc/logrotate.d/
```
