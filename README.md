# フリーメモ

# **LACAN(Lightweight Accountable and Anonymity Netoworking)**

---

このリポジトリは「Making Accountability in Anonymous Networks Real」で提案されたLACANをC言語で実装したライブラリである．詳細な処理は当該論文のAppendixの「A Protocol Specification
」に示しており，このライブラリはそれらをもとに実装している．

このリポジトリは以下を確認できる．

- LACANの経路設定フェーズ，データ転送フェーズ，通報フェーズにおける全ノード(S,R,Ni,V)のレイテンシ
- データ転送フェーズのリレーNiのスループット

## 事前準備

このリポジトリは以下のパッケージがインストールされていることを前提としている

- OpenSSL
- DPDK
- Traceable Signatures［1］

LACANでは追跡可能署名を用いるためhttps://github.com/scmanjarrez/libgroupsig
を用いてインストールする

実装はubuntu22.05とDPDK20.05を用いてテストしている

```jsx
git clone 
```

DPDKのリンク確立のために以下を実行

```jsx
./dpdk-setup-100g.sh
```

### **コンパイル方法**

経路設定フェーズMakefileを用いて実行ファイル(dpdk_test)を生成して実行

通報フェーズはg++で実行ファイルを生成して実行

## コード説明

**簡便のため，以下は共有しているものとする**

- 全てのアドレス
- MACやTLS用のIVやタグ(FIXED_IV….)(すべて同じ)
- DH公開鍵やEd25519公開鍵(すべて同じ)

(セッション鍵用のIVやタグはペイロードに含める)

実装コードは以下のとおりである

- common_func: 共通関数
- TLS_func:　通報(vr)フェーズで用いる関数
- DPDK_func: 経路設定(ps)、データ転送(dt)で用いる関数
- key_st: 鍵格納フォルダ
- key_setup.cpp: 各種鍵やリストの生成
- ps_sender/receiver.cpp: 経路設定フェーズの送信者(トラフィック生成)と受信者(処理するリレー)
- dt_sender/receiver.cpp: データ転送フェーズの送信者(トラフィック生成)と受信者(処理するリレー)
- vr_R/V/Ni.cpp: 通報フェーズの受信者、検証者、各リレーの処理

## 実行方法例

### 鍵準備

key_setup.cppを実行し各種暗号で使用する以下の鍵やリストを生成しPEM形式で保存する

- DHの秘密鍵 dh_sec
- Ed25519の秘密鍵/公開鍵 ed25519_sec/pub
- USの秘密値(鍵) us_x
- 追跡可能署名のグループ秘密鍵/公開鍵 mgrkey/grpkey
- 追跡可能署名のメンバの秘密鍵 memkey

※CRLはReveal時に生成する

### 経路設定フェーズ

追跡可能署名をパケットに乗せるためジャンボフレームに対応させる

**ジャンボフレーム対応手順**

送信側ではmainrev.cpp、受信側ではmainrev.cppを実行

Makefileで上記ファイルを指定し以下のように実行

```jsx
make
./run.sh
```

**レイテンシ**

受信側で受信パケット数n_all_rxの上限を調整してNiの平均レイテンシを算出できる

例:

### データ転送フェーズ

送信側はmainrev.cpp、受信側はmainrev.cpp

Makefileで上記ファイルを指定し以下のように実行

```jsx
make
./run.sh
```

**レイテンシ**

受信側の受信パケット数n_all_rxの上限を調整してNiの平均レイテンシを算出できる

例:

**スループット**

送信側で送信開始から受信までの秒数を調整し送受信パケット比(パケットロス)が1%まで

run.shの送信レートをあげる

ペイロードはrun.shのframesize、common_func.hの**MAX_PTXT**で調整

例: 

### **通報フェーズ**

受信者はRpathset.cpp、検証者はVAcc、各リレーはRiAcc

※RiAccはリレー数ROUTERSのときN_ROUTERSを表し前ノードとしてN_1を返すようにしている 

```jsx
g++ VAcc.cpp common_func.c TLS_func.c -lcrypto -lgroupsig -lrte_eal -lm -lz -o VAcc
./VAcc
```

なお、サイクル数計測でrte_rdtscを用いるため-lrte_ealを含めている

**レイテンシ**

受信者側で通報パケット数pkt_countを調整してVとNiの処理の平均レイテンシを算出できる

例:
