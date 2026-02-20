# PCAP_analyzer

- PCAPファイルをアップロードして解析し、シーケンス図などに変換するWebツール。
- Open AI の API Keyを設定することで、AIにパケット解析を行わせ、説明とセキュリティ警告があるかを含めて確認できる。

## 使い方
1. リポジトリをクローン
2. `pip install -r requirements.txt` で依存関係をインストール
3. `python app.py` で起動
4. ブラウザで `http://127.0.0.1:5000` にアクセス