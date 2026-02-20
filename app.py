import os
from flask import Flask, render_template, request, redirect, url_for
import pyshark
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Limit upload size to 16MB

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_pcap_to_mermaid(filepath):
    """
    Parses a pcap file using pyshark, groups into sessions, and returns a list of sessions:
    [
        {'id': 'TCP-0', 'label': '...', 'mermaid': '...'},
        ...
    ]
    """
    sessions = {} # Key: stream_id, Value: { type, src, dst, packets: [] }

    try:
        cap = pyshark.FileCapture(filepath, keep_packets=False)
        
        MAX_GLOBAL_PACKETS = 2000 # Safety limit
        count = 0

        for packet in cap:
            if count > MAX_GLOBAL_PACKETS: break
            count += 1
            
            try:
                # 1. Identify Stream / Session ID
                stream_id = "Other"
                protocol = "Unknown"
                
                # Check for Transport Layer Stream ID
                if 'TCP' in packet:
                    protocol = "TCP"
                    # pyshark stores stream index in packet.tcp.stream
                    if hasattr(packet.tcp, 'stream'):
                        stream_id = f"TCP-{packet.tcp.stream}"
                elif 'UDP' in packet:
                    protocol = "UDP"
                    # pyshark stores stream index in packet.udp.stream
                    if hasattr(packet.udp, 'stream'):
                        stream_id = f"UDP-{packet.udp.stream}"
                elif 'ICMP' in packet:
                    protocol = "ICMP"
                    stream_id = "ICMP-Traffic"
                elif 'ARP' in packet:
                    protocol = "ARP"
                    stream_id = "ARP-Traffic"
                
                # Initialize session if new
                if stream_id not in sessions:
                    sessions[stream_id] = {
                        'id': stream_id,
                        'protocol': protocol,
                        'participants': set(),
                        'packets': [],
                        'packet_count': 0,
                        'dst_ports': set()
                    }

                # 2. Extract Packet Info
                src = None
                dst = None
                info = ""
                length = "0"
                timestamp = getattr(packet, 'sniff_time', None)
                highest_layer = packet.highest_layer
                
                # Extract Ports if available
                dst_port = ""
                if 'TCP' in packet and hasattr(packet.tcp, 'dstport'):
                    dst_port = packet.tcp.dstport
                elif 'UDP' in packet and hasattr(packet.udp, 'dstport'):
                    dst_port = packet.udp.dstport

                if 'IP' in packet:
                    src = packet.ip.src
                    dst = packet.ip.dst
                    length = packet.length
                    if hasattr(packet, 'info'): info = packet.info
                    elif hasattr(packet, 'length'): info = f"Len: {packet.length}"
                elif 'IPV6' in packet:
                    src = packet.ipv6.src
                    dst = packet.ipv6.dst
                    length = packet.length
                    if hasattr(packet, 'info'): info = packet.info
                elif 'ARP' in packet:
                    src = packet.arp.src_proto_ipv4
                    dst = packet.arp.dst_proto_ipv4
                    length = packet.length
                    info = f"Who matches {dst}?"
                    if packet.arp.opcode == '2':
                         info = f"{src} is at {packet.arp.src_hw_mac}"
                    highest_layer = "ARP"

                if not src or not dst:
                    continue
                
                # Store Port
                if dst_port:
                    sessions[stream_id]['dst_ports'].add(str(dst_port))
                
                # Normalize IPs for mermaid (no dots/colons)
                def clean_id(s):
                    return str(s).replace(":", "_").replace(".", "_").replace("-", "_")

                src_id = clean_id(src)
                dst_id = clean_id(dst)
                
                sessions[stream_id]['participants'].add((src_id, str(src)))
                sessions[stream_id]['participants'].add((dst_id, str(dst)))

                # Store packet data for this session
                sessions[stream_id]['packets'].append({
                    'time': str(timestamp) if timestamp else "",
                    'src': str(src),
                    'dst': str(dst),
                    'length': str(length),
                    'src_id': src_id,
                    'dst_id': dst_id,
                    'protocol': highest_layer,
                    'info': str(info),
                    'raw_proto': protocol
                })
                sessions[stream_id]['packet_count'] += 1

            except Exception as e:
                continue
        
        cap.close()

    except Exception as e:
        return []

    # 3. Generate Mermaid for each session
    results = []
    
    for s_id, data in sessions.items():
        if data['packet_count'] == 0: continue
        
        # Build Mermaid String
        lines = [
            "sequenceDiagram",
            "    autonumber"
        ]
        
        # Participants aliases
        sorted_participants = sorted(list(data['participants']))
        
        # Determine Label
        label_parts = [p[1] for p in sorted_participants[:2]]
        session_label = f"{data['protocol']} Stream"
        if len(label_parts) == 2:
            session_label = f"{label_parts[0]} ↔ {label_parts[1]}"
        elif len(label_parts) == 1:
            session_label = f"{label_parts[0]}"
        
        if data['protocol'] != "Unknown":
             session_label += f" ({data['protocol']})"

        for pid, real_ip in sorted_participants:
             lines.append(f"    participant {pid} as {real_ip}")
        
        # Packet Lines
        MAX_SESSION_PACKETS = 50
        for i, pkt in enumerate(data['packets']):
            if i >= MAX_SESSION_PACKETS:
                lines.append(f"    Note over {data['packets'][0]['src_id']}: ... Truncated ({len(data['packets'])} total) ...")
                break
            
            # Icon logic
            icon = ""
            arrow = "->>"
            p_upper = str(pkt['protocol']).upper()
            info_txt = str(pkt['info'])

            if "HTTP" in p_upper:
                icon = "🌐"
                arrow = "-->>" if "HTTP/1.1 2" in info_txt or "HTTP/1.1 3" in info_txt else "->>"
            elif "TLS" in p_upper or "SSL" in p_upper:
                icon = "🔒"
            elif "DNS" in p_upper:
                icon = "🔍"
            elif "TCP" in p_upper:
                icon = "🔌"
            elif "SYN" in info_txt: 
                icon = "✨"
            
            # Shorten/Wrap Info
            # Wrap text every N characters to avoid super wide diagrams
            wrap_limit = 50
            if len(info_txt) > wrap_limit:
                # Chunk the string
                chunks = [info_txt[i:i+wrap_limit] for i in range(0, len(info_txt), wrap_limit)]
                info_txt = "<br/>".join(chunks)
            
            lines.append(f"    {pkt['src_id']}{arrow}{pkt['dst_id']}: {icon} **{pkt['protocol']}** <br/> {info_txt}")
        
        # Format Ports
        port_list = list(data.get('dst_ports', []))
        # Sort ports numerically if possible
        try:
            port_list.sort(key=int)
        except:
            port_list.sort()
            
        port_str = ",".join(port_list[:5]) # Top 5 ports
        if len(port_list) > 5:
            port_str += "..."

        results.append({
            'id': clean_id(s_id), 
            'display_id': s_id,
            'label': session_label,
            'packet_count': data['packet_count'],
            'mermaid': "\n".join(lines),
            'packets': data['packets'],
            'dst_port': port_str
        })
    
    # Sort results desc by packet count
    results.sort(key=lambda x: x['packet_count'], reverse=True)
    
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    sessions = []
    error = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            error = 'No file part'
            return render_template('index.html', error=error)
        
        file = request.files['file']
        
        if file.filename == '':
            error = 'No selected file'
            return render_template('index.html', error=error)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            sessions = parse_pcap_to_mermaid(filepath)
            
            if not sessions:
                 error = "No analyzable packets found in file."
            
            # os.remove(filepath) 
        else:
            error = 'Invalid file type. Allowed: .pcap, .pcapng, .cap'

    return render_template('index.html', sessions=sessions, error=error)


@app.route('/analyze', methods=['POST'])
def analyze_session():
    data = request.json
    api_key = data.get('api_key')
    session_data = data.get('session_data') 
    language = data.get('language', 'en')
    mode = data.get('mode', 'normal') # 'normal' or 'security'
    
    if not api_key:
        return {'error': 'API Key is required in Settings'}, 400
    
    try:
        import openai
    except ImportError:
        return {'error': 'Python "openai" library is not installed. Server admin must run: pip install openai'}, 500

    try:
        client = openai.OpenAI(api_key=api_key)
        
        lang_instruction = "Respond in English."
        if language == 'ja':
            lang_instruction = "Respond in Japanese (日本語で答えてください)."

        if mode == 'security':
            prompt = f"""
            You are a Cybersecurity Analyst. Review the following summary of network sessions captured from a PCAP file.
            Perform a comprehensive security assessment.
            
            **Formatting Instructions:**
            - Use `[CRITICAL]` for high-risk findings (e.g. cleartext passwords, malware).
            - Use `[WARNING]` for suspicious activities (e.g. scanning, non-standard ports).
            - Use `[INFO]` for general observations.
            - Use `[SAFE]` if a protocol or behavior is verified as normal.
            - Wrap important keywords (IPs, Ports, Protocols) in `backticks`.
            
            Your analysis should include:
            1.  **Overview**: What is the general purpose of this traffic?
            2.  **Risk Identification**: Apply the tags above to findings.
            3.  **Anomalies**: Any unusual ports or volume of traffic?
            4.  **Recommendations**: what logical steps should be taken next?
            
            {lang_instruction}
            
            Session Summary:
            {session_data}
            """
        else:
            prompt = f"""
            You are a network analysis expert. Analyze the following packet summary of a network session.
            Explain what is happening in this session in simple terms suitable for a developer.
            Highlight the protocol flow, any handshake (SYN/ACK), and data transfer.
            {lang_instruction}
            
            Packet Summary:
            {session_data}
            """
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a network analysis expert."},
                {"role": "user", "content": prompt}
            ]
        )
        
        explanation = response.choices[0].message.content
        return {'explanation': explanation}
        
    except Exception as e:
        # Fallback for older openai versions or other errors
        return {'error': f"AI Error: {str(e)}"}, 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
