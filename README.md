# PCAP 文件加密套件扫描工具
[English](#pcap-file-cipher-suite-scanner-tool )
## 用法
```
parse_pcap_cipher_suites.exe -h
usage: parse_pcap_cipher_suites.exe [-h] [-T TSHARK_PATH] -r PCAP_FILE [-p {tls,dtls}] [-d PORT [PORT ...]]
parse pcap file to xlsx
optional arguments:
  -h, --help            show this help message and exit
  -T TSHARK_PATH, --tshark TSHARK_PATH
                        set tshark.exe path
  -r PCAP_FILE, --pcap PCAP_FILE
                        set pcap file path
  -p {tls,dtls}, --proto {tls,dtls}
                        set protocol tls or dtls
  -d PORT [PORT ...], --port PORT [PORT ...]
                        set ports list ,like --port 5684,5683
```
### 解析 tls 协议的加密套件
```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p tls
```
将8089端口解码为tls，并且解析其加密套件
```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p tls -d 8089
```
### 解析 dtls 协议的加密套件
```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p dtls
```
将5684端口解码为dtls，并且解析其加密套件
```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p dtls -d 5684
```
## 输出
输出为xlsx文件，文件名为`report/cipher_suites_{args.proto}_{timestamp}.xlsx`
输出Excel文件格式为：
1. tls
    'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tls.handshake.type','tls.handshake.extensions_server_name', 'secure cipher suites','insecure cipher suites'
2. dtls
    'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'dtls.handshake.type','secure cipher suites','insecure cipher suites'
'secure cipher suites','insecure cipher suites'为加密套件列表，一行一个套件，Reserved“Reserved({code})”形式例如`Reserved(0xfafa)`
## 数据
### tls-parameters-4.csv
从[IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)下载的加密套件列表，用于将16进制的加密套件编码转换程字符串形式的加密套件名称
默认情况下请不要修改
### secure_tls_cipher_suites.csv
安全的加密套件列表，一行一个套件，可以按需修改

## 依赖包
- python3
- tshark.exe (Wireshark自带)
- xlsxwriter
===========================
English
===========================
# PCAP File Cipher Suite Scanner Tool
This is a simple utility tool for scanning the encryption suites of TLS and DTLS in pcap files.

## Usage
```parse_pcap_cipher_suites.exe -h
usage: parse_pcap_cipher_suites.exe [-h] [-T TSHARK_PATH] -r PCAP_FILE [-p {tls,dtls}] [-d PORT [PORT ...]]
parse pcap file to xlsx
optional arguments:
  -h, --help            show this help message and exit
  -T TSHARK_PATH, --tshark TSHARK_PATH
                        set tshark.exe path
  -r PCAP_FILE, --pcap PCAP_FILE
                        set pcap file path
  -p {tls,dtls}, --proto {tls,dtls}
                        set protocol tls or dtls
  -d PORT [PORT ...], --port PORT [PORT ...]
                        set ports list ,like --port 5684,5683
```
## Parsing Encryption Suites for TLS protocol
```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p tls
```
Decodes the TLS traffic in the pcap file and parses the encryption suites.
```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p tls -d 8089
```
Decodes the TLS traffic on port 8089 and parses the encryption suites.

## Parsing Encryption Suites for DTLS Protocol
```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p dtls
```
Decodes the DTLS traffic in the pcap file and parses the encryption suites.

```
parse_pcap_cipher_suites.exe -T "D:\Program Files\Wireshark\tshark.exe" -r .\1.pcap -p dtls -d 5684
```
Decodes the DTLS traffic on port 5684 and parses the encryption suites.

## Output
The output is an xlsx file with the filename report/cipher_suites_{args.proto}_{timestamp}.xlsx. The Excel file format is as follows:

1. For TLS:
'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tls.handshake.type', 'tls.handshake.extensions_server_name', 'secure cipher suites', 'insecure cipher suites'
2. For DTLS:
'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'dtls.handshake.type', 'secure cipher suites', 'insecure cipher suites'
The 'secure cipher suites' and 'insecure cipher suites' are lists of encryption suites, with one suite per line. Reserved suites are represented as "Reserved({code})", for example, Reserved(0xfafa).

## Data
### tls-parameters-4.csv
The encryption suite list downloaded from [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml). It is used to convert hexadecimal-encoded cipher suite codes to their corresponding string names. Please do not modify it by default.

### secure_tls_cipher_suites.csv
A list of secure encryption suites, with one suite per line. You can modify it as per your requirements.

## Dependencies
- python3
- tshark.exe (included with Wireshark)
- xlsxwriter
