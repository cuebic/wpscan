# README.md

## 機能概要

WORDPRESS の脆弱性 TSV 形式でリスト化します。

## 前提事項

* MainWP プラグインのデータベースを使用するため、MainWP に WORDPRESS が登録されていること

> https://mainwp.com/

## 定期実行

スクリプトを実行するサーバで、次のように ログディレクトリの作成と CRON の登録を行います。

root ユーザで実行する。

```
mkdir /var/log/wpscan
chown ubuntu:ubuntu /var/log/wpscan
```

ubuntu ユーザで実行する。

```
crontab -e

0 12 * * * /bin/bash -l /home/kusanagi/wpscan/wpscan.sh > /var/log/wpscan/wpscan.log 2>&1
```

## ログローテーション

スクリプトを実行するサーバで、次のようにログローテーションの登録を行います。

root ユーザで実行する。

```
cp logrotate.d/wpscan /etc/logrotate.d/
```
