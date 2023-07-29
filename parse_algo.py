import argparse
import csv
import logging
import os.path
import shutil
import subprocess
import time
from typing import Optional

import xlsxwriter

# log.debug start
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='[%Y-%m-%d %H:%M:%S]',
                    filemode='w')
# log.debug end

DATA_PATH = './data/'
TEMPLATE_PATH = './templates/cipher_suites.xlsx'
TSHARK_PATH = r'D:\Program Files\Wireshark\tshark.exe'


def parse_cipher_suites_mapping():
    # parse tls-parameters-4.csv
    # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    logging.debug('parse cipher suites mapping from tls-parameters-4.csv')
    mappings = {}
    with open(os.path.join(DATA_PATH, 'tls-parameters-4.csv'), 'r') as f:
        tls_params = csv.reader(f)
        for row in tls_params:
            # tls_params file start example
            # Value,Description,DTLS-OK,Recommended,Reference
            # "0x00,0x00",TLS_NULL_WITH_NULL_NULL,Y,N,[RFC5246] -> parse into {'0x0000': 'TLS_NULL_WITH_NULL_NULL'}
            # "0x00,0x01",TLS_RSA_WITH_NULL_MD5,Y,N,[RFC5246]  -> parse into {'0x0001': 'TLS_RSA_WITH_NULL_MD5'}
            # parse row
            if row[0] == 'Value':
                continue
            mappings[row[0].replace(',0x', '').lower()] = row[1]
    return mappings


def read_secure_cipher_suites():
    # parse secure-cipher-suites.csv
    logging.debug('parse secure cipher suites from secure-cipher-suites.csv')
    suites = []
    with open(os.path.join(DATA_PATH, 'secure_tls_cipher_suites.csv'), 'r') as f:
        secure_suites = csv.reader(f)
        for row in secure_suites:
            # secure_suites file start example
            # TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256
            # parse row
            suites.extend(row)
    return suites

def parse_pcap_to_xlsx(proto: str,  # tls or dtls
                       pcap_file_path: str,  # pcap file path
                       workbook_writer: xlsxwriter.Workbook,  # xlsx writer
                       proto_port: Optional[tuple] = None  # dtls port
                       ):
    if proto == 'tls':  # for tls
        worksheet = workbook_writer.add_worksheet('TLS加密套件扫描')
        worksheet.write_row(0, 0, ['ip src', 'ip dst', 'tcp src port', 'tcp dst port',
                                   'type', 'server name', 'secure cipher suites', 'insecure cipher suites'])
        next_row = 0
        pcap_filter = 'tls.handshake.type == 1 or tls.handshake.type == 2'
        field_list = [
            'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tls.handshake.type',
            'tls.handshake.extensions_server_name', 'tls.handshake.ciphersuite']
        packet_type = {'': '', '1': 'client_hello', '2': 'server_hello'}
        fields = [item for sublist in [['-e', x] for x in field_list] for item in sublist]
        selectors = []
        if proto_port:
            selectors = [item for sublist in [['-d', f'tcp.port=={x},tls'] for x in proto_port] for item in sublist]
        command = [TSHARK_PATH, '-r', pcap_file_path, '-Tfields'] + \
                  selectors + fields + ['-Y', pcap_filter]  # tshark -Y is used to filter the packets
    elif proto == 'dtls':  # for dtls
        worksheet = workbook_writer.add_worksheet('DTLS加密套件扫描')
        worksheet.write_row(0, 0, ['ip src', 'ip dst', 'udp src port', 'udp dst port',
                                   'type', 'secure cipher suites', 'insecure cipher suites'])
        next_row = 0
        pcap_filter = 'dtls.handshake.type == 1 or dtls.handshake.type == 2'
        field_list = [
            'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'dtls.handshake.type',
            'dtls.handshake.ciphersuite']
        packet_type = {'': '', '1': 'client_hello', '2': 'server_hello'}
        fields = [item for sublist in [['-e', x] for x in field_list] for item in sublist]
        selectors = []
        if proto_port:
            selectors = [item for sublist in [['-d', f'udp.port=={x},dtls'] for x in proto_port] for item in sublist]
        command = [TSHARK_PATH, '-r', pcap_file_path, '-Tfields'] + \
                  selectors + fields + ['-Y', pcap_filter]
    else:
        raise NotImplementedError(proto)
    logging.debug(' '.join(command))
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        # tls line format:
        # 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tls.handshake.type','tls.handshake.extensions_server_name', 'tls.handshake.ciphersuite'
        # dtls line format:
        # 'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'dtls.handshake.type','dtls.handshake.ciphersuite'
        # parse line into list
        line = line.decode('utf-8').strip().split('\t')
        # change handshake.type into name 1:client_hello 2:server_hello
        line[4] = packet_type.get(line[4], 'unknown')
        # parse ciphersuite into list
        cipher_suite_codes = line[-1].split(',')
        secure_cipher_suites_names = []
        insecure_cipher_suites_names = []
        for code in cipher_suite_codes:
            name = CIPHER_SUITE_MAPPING.get(code, 'unknown')
            if not name.startswith('TLS'):
                name += f'({code})'
            if name in SECURE_CIPHER_SUITES[0]:
                secure_cipher_suites_names.append(name)
            else:
                insecure_cipher_suites_names.append(name)
        # write into xlsx
        next_row += 1
        row = line[:-1] + ['\r\n'.join(secure_cipher_suites_names), '\r\n'.join(insecure_cipher_suites_names)]
        worksheet.write_row(next_row, 0, row)


def parse_args():
    parser = argparse.ArgumentParser(description='parse pcap file to xlsx')
    default_tshark_path = r'C:\Program Files\Wireshark\tshark.exe'
    parser.add_argument('-T', '--tshark', dest='tshark_path', default=default_tshark_path, help='set tshark.exe path')
    parser.add_argument('-r', '--pcap', dest='pcap_file', required=True, help='set pcap file path')
    parser.add_argument('-p', '--proto', dest='proto', default='tls', choices=['tls', 'dtls'],
                        help='set protocol tls or dtls')
    # comma splited port list
    parser.add_argument('-d', '--port', dest='port', nargs='+', type=str, help='set ports list ,like --port 5684,5683')
    return parser.parse_args()


if __name__ == '__main__':
    logging.info('Start to parse pcap cipher suites to xlsx')
    args = parse_args()
    # print(args)

    CIPHER_SUITE_MAPPING = parse_cipher_suites_mapping()
    SECURE_CIPHER_SUITES = read_secure_cipher_suites()

    timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime())
    output_xlsx = shutil.copy(TEMPLATE_PATH, f'report/cipher_suites_{args.proto}_{timestamp}.xlsx')
    # get a xlsx writer
    writer = xlsxwriter.Workbook(output_xlsx)
    parse_pcap_to_xlsx(args.proto, args.pcap_file, writer, proto_port=args.port)
    writer.close()
    logging.info(f'Finished, save report to {output_xlsx}')
    logging.info('Press Enter to exit')
    input()
