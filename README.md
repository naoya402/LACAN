# **LACAN(Lightweight Accountable and Anonymity Networking)**

---

このリポジトリは「Making Accountability in Anonymous Networks Real」で提案されたLACANをC言語で実装したライブラリである．詳細な処理は論文のAppendixの「A Protocol Specification」に示しており，このライブラリはそれらをもとに実装している．

このリポジトリは以下を確認できる．

- LACANの経路設定フェーズ，データ転送フェーズ，通報フェーズにおける全ノード(S,R,Ni,V)のレイテンシ
- データ転送フェーズのリレーNiのスループット

## 事前準備

このリポジトリは以下のパッケージがインストールされていることを前提としている

- OpenSSL
- DPDK
- libgroupsig

LACANでは追跡可能署名(Traceable Signatures)を用いるためhttps://github.com/scmanjarrez/libgroupsig
を用いてlibgroupsigをインストールする

実装はUbuntu22.05とOpenSSL1.1.1、DPDK20.05を用いてテストしている

```jsx
git clone https://github.com/naoya402/LACAN.git
```

DPDKのリンク確立のために以下を実行

```jsx
./dpdk-setup-100g.sh
```

### **コンパイル方法**

経路設定フェーズMakefileを用いて実行ファイル(dpdk_test)を生成してrun.shで実行

run.sh内の引数
```jsx
./build/dpdk_test [-c <coremask>] [-n <channels>] -- [--lcores <lcores>] [--tx_rate <rate>] [--frame_size <size>] [--userset <userset>]
```
#### coremask
使用するCPUコアをビットマスクで指定し特定の論理コアを有効化

#### channels
システムのメモリチャネル数を指定

#### lcores
EAL引数の一部で、サービスに使用する論理コアの範囲を指定

#### rate
パケットの送信レート(pps)を指定

#### size
送信されるイーサネットフレームのサイズ（バイト）を指定

#### userset
 (Port ID, Queue ID, lcore ID)をタプル形式で指定


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

送信側ではps_sender.cpp、受信側ではps_receiver.cppを実行

Makefileで上記ファイルを指定し以下のように実行

```jsx
make
./run.sh
```

#### 出力

受信側で受信パケット数n_all_rxの上限を調整してNiの平均レイテンシを算出できる

例:
```jsx

```

### データ転送フェーズ

送信側はdt_sender.cpp、受信側はdt_receiver.cpp

Makefileで上記ファイルを指定し以下のように実行

```jsx
make
./run.sh
```

#### 出力

受信側の受信パケット数n_all_rxの上限を調整してNiの平均レイテンシを算出できる

例:
```jsx

```


送信側で送信開始から受信までの秒数を調整し送受信パケット比(パケットロス)が1%まで

run.shの送信レートをあげる

例: 
```jsx

```

### **通報フェーズ**

受信者はvr_R.cpp、検証者はvr_V.cpp、各リレーはvr_Ni.cpp

※vr_Niはリレー数ROUTERSのときN_ROUTERSを表し前ノードとしてN_1を返すようにしている 

```jsx
g++ vr_Ni.cpp common_func.c TLS_func.c -lcrypto -lgroupsig -lrte_eal -lm -lz -o vr_Ni
./VAcc
```

なお、サイクル数計測でrte_rdtscを用いるため-lrte_ealを含めている

#### 出力

受信者側で通報パケット数pkt_countを調整してVとNiの処理の平均レイテンシを算出できる

例(リレー数 n＝3):

V
```jsx
Average Report processing cycles: 1752471.00 (473.64 µs)
Average Open cycles: 1320892.00 (357.00 µs)
Average US_NIZK_Confirm cycles: 15390323.00 (4159.55 µs)
Average US_NIZK_Disavow cycles: 2236230.00 (604.39 µs)
Average Com_Verify cycles: 6833.00 (1.85 µs)
Average τ_verify cycles: 670654.00 (181.26 µs)
Average Reveal cycles: 15024.89 (4.07 µs)
Average Trace cycles: 10411069.87 (2816.85 µs)
Average Inquiry processing cycles: 18307682.00 (4948.02 µs)
```
Ni
```jsx
Average US_NIZK_Confirm cycles: 2675276.00 (1337.64 µs)
Average US_NIZK_Disavow cycles: 3137534.00 (1568.77 µs)
Average Relay processing cycles: 5836891.00 (2918.45 µs)
```
