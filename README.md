# PCAP_analyzer

[日本語](#japanese) | [English](#english)

---

<a id="japanese"></a>
## 日本語 (Japanese)

PCAPファイルをWebインターフェース経由でアップロードし、パケット解析を行ってMermaid.js形式のシーケンス図などに変換・表示するツールです。
さらに、OpenAI APIを連携させることで、AIによるパケットの詳細解説やセキュリティリスクの診断が可能です。

### 主な機能
* **パケット可視化**: PCAP / PCAPNG / CAPファイルを解析し、シーケンス図を自動生成
* **AI解析サポート**: OpenAI API Keyを設定することで、通信内容の説明やセキュリティ警告の有無を確認可能
* **Web GUI**: Flaskによる直感的な操作画面
* **パケット解析**: PyShark (tshark wrapper) を使用

### 使い方
1. **リポジトリをクローン:**
   `git clone https://github.com/kikuta/PCAP_analyzer.git`
   `cd PCAP_analyzer`

2. **依存関係のインストール:**
   `pip install -r requirements.txt`
   *注: tshark がシステムにインストールされている必要があります。*

3. **アプリケーションの起動:**
   `python app.py`

4. **アクセス:**
   ブラウザで http://127.0.0.1:5000 にアクセスしてください。

---

<a id="english"></a>
## English

PCAP_analyzer is a web-based tool designed to upload and analyze packet capture files, converting them into visual representations like Mermaid.js sequence diagrams. 
By configuring an OpenAI API Key, users can leverage AI to provide detailed packet descriptions and check for security warnings.

### Key Features
* **Packet Visualization**: Automatically generates sequence diagrams from PCAP, PCAPNG, and CAP files.
* **AI-Powered Analysis**: Integrates with OpenAI API to provide communication explanations and security risk assessments.
* **Web GUI**: User-friendly interface powered by Flask.
* **Deep Inspection**: Uses PyShark (tshark wrapper) for packet analysis.

### Usage
1. **Clone the repository:**
   `git clone https://github.com/kikuta/PCAP_analyzer.git`
   `cd PCAP_analyzer`

2. **Install dependencies:**
   `pip install -r requirements.txt`
   *Note: Ensure tshark is installed on your system.*

3. **Run the application:**
   `python app.py`

4. **Access:**
   Open your browser and navigate to http://127.0.0.1:5000.

---

## License
Apache License 2.0