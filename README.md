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
* **検索機能**: 解析されたパケットデータから特定のプロトコルやキーワードでフィルタリングが可能
* **マルチリンガルUI**: 日本語と英語の表示を切り替えて利用可能
* **Web GUI**: Flaskによる直感的な操作画面

### Web UI の構成例
* **ダッシュボード**: アップロードしたファイルの一覧と解析ステータス
* **解析ビュー**: 左側にパケットリスト、右側にMermaid形式のシーケンス図を表示
* **AI診断エリア**: 解析結果に基づいたAIのコメントとセキュリティ警告を表示

<img width="800" alt="Flask web app" src="https://github.com/user-attachments/assets/bbd32a7c-af76-4e98-bda5-420fb1928b69" />

<img width="800" alt="Flask web app" src="https://github.com/user-attachments/assets/16a24a0d-0877-46e2-abb4-bd2d2f403e9a" />

<img width="800" alt="Flask web app" src="https://github.com/user-attachments/assets/256df95c-3ffe-4ac4-837f-ecf625e9b304" />

<img width="800" alt="Flask web app" src="https://github.com/user-attachments/assets/3f6a4f17-5401-4c8f-899b-72e84fcde550" />

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
* **Search Functionality**: Filter through analyzed packet data by protocol or keywords.
* **Multilingual UI**: Easily toggle between Japanese and English interface.
* **Web GUI**: User-friendly interface powered by Flask.

### Web UI Example
* **Dashboard**: List of uploaded files and their analysis status.
* **Analysis View**: Packet list on the left, Mermaid sequence diagram on the right.
* **AI Diagnosis Area**: AI-generated comments and security alerts based on analysis.

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