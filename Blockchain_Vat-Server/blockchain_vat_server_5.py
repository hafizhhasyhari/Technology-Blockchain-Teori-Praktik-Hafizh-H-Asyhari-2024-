# Import
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from collections import OrderedDict
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import json
import binascii
import hashlib
import requests

# Header setiap berhasil mining
pesan_mining = "Blok baru dari" # Notifikasi blok baru
tingkat_kerumitan_mining = 5 # menentukan tingkat kerumitan


class Blockchain:

    def __init__(self):
        self.faktur_pajak = [] # daftar faktur_pajak yang akan ditambahkan pada blok berikutnya
        self.chain = [] # data blockchain_vat_server
        self.nodes = set() # set() agar list tidak terurut, hasil yang ditampilkan akan tidak urut
        self.node_id = str(uuid4()).replace('-', '') #membuat nomor acak untuk alamat komputer

        # Membuat genesis blok
        self.buat_block(0, '00')

    def tambah_node(self, node_url):
        """
        untuk menambahkan node baru
        """
        # Cek node_url dalam format yang benar
        tambah_url = urlparse(node_url)
        if tambah_url.netloc:
            self.nodes.add(tambah_url.netloc)
        elif tambah_url.path:
            # Menerima URL tanpa format seperti '192.168.0.5:5000'
            self.nodes.add(tambah_url.path)
        else:
            raise ValueError('URL tidak ditemukan')

    def buat_block(self, nonce, hash_sebelumnya):
        """
        menambahkan daftar faktur kedalam blockchain_vat_server
        """
        data_blok = {'nomor_blok': len(self.chain) + 1,
                 'timestamp': time(),
                 'faktur_pajak': self.faktur_pajak,
                 'nonce': nonce, # number only once
                 'hash_sebelumnya': hash_sebelumnya}

        # Reset the current list of faktur_pajak
        self.faktur_pajak = []
        self.chain.append(data_blok)
        return data_blok

    def verifikasi_digital_signature(self, pengusaha_public_key, digital_signature, faktur):
        """
        Cek penandatanganan menggunakan kunci publik (pengusaha_public_key)
        """
        public_key = RSA.importKey(binascii.unhexlify(pengusaha_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(faktur).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(digital_signature))
            return True
        except ValueError:
            return False

    @staticmethod
    def bukti_validasi(faktur_pajak, hash_sebelumnya, nonce, kerumitan=tingkat_kerumitan_mining):
        """
        Cek jika nilai hash sesuai dengan nilai mining. Fungsi ini akan dijalankan dalam proof_of_work.
        """
        bukti = (str(faktur_pajak) + str(hash_sebelumnya) + str(nonce)).encode('utf8')
        # utf-8 adalah byte encoding, mengubah str "Hello, World!" --> b"Hello, World!"
        h = hashlib.new('sha256')
        h.update(bukti)
        ekstrasi_hash = h.hexdigest() # hexdigest() akan memproses sidik hash dan mengumpan balik nilai dalam nilai hexadecimal
        return ekstrasi_hash[:kerumitan] == '0' * kerumitan # misal kerumitan=2 maka dimulai dengan 00 pada MSB hash

    def proof_of_work(self):
        """
        Algoritma proof of work
        """
        blok_sebelumnya = self.chain[-1]
        hash_sebelumnya = self.hash(blok_sebelumnya)
        nonce = 0
        while self.bukti_validasi(self.faktur_pajak, hash_sebelumnya, nonce) is False:
            nonce += 1
        return nonce

    @staticmethod
    def hash(data_blok):
        """
        Digunakan untuk membuat hash SHA-256 pada blok
        """
        # Memastikan dictionary tersusun urut, jika tidak maka hash akan tidak konsisten
        urutan_blok = json.dumps(data_blok, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(urutan_blok)
        return h.hexdigest()

    def update_blok_terpanjang(self):
        """
        Mengatasi masalah antar node blockchain dengan menggunakan blok terpanjang
        """
        daftar_nodes = self.nodes
        chain_baru = None

        # Mencari blok terpanjang
        panjang_maksimum = len(self.chain)

        # Mengambil dan verifikasi '/chain' terpanjang dari keseluruhan node dalam blockchain
        for node in daftar_nodes:
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                panjang_blok = response.json()['panjang_blok']
                chain = response.json()['chain']

                # Update panjang_maksimum
                if panjang_blok > panjang_maksimum and self.valid_chain(chain):
                    panjang_maksimum = panjang_blok
                    chain_baru = chain

        # Mengganti dengan chain atau blok terpanjang
        if chain_baru:
            self.chain = chain_baru
            return True

        return False

    def valid_chain(self, chain):
        """
        Cek jika blockchain valid
        """
        blok_sebelumnya = chain[0]
        index_sekarang = 1

        while index_sekarang < len(chain):
            blok = chain[index_sekarang]
            if blok['hash_sebelumnya'] != self.hash(blok_sebelumnya):
                return False

            faktur_pajak = blok['faktur_pajak'][:-1]
            data_faktur = ['pengusaha_public_key', 'pembeli_public_key', 'ppn']
            faktur_pajak = [OrderedDict((k, faktur[k]) for k in data_faktur) for faktur in
                            faktur_pajak]

            if not self.bukti_validasi(faktur_pajak, blok['hash_sebelumnya'], blok['nonce'], tingkat_kerumitan_mining):
                return False

            blok_sebelumnya = blok
            index_sekarang += 1

        return True

    def kirim_faktur(self, pengusaha_public_key, pembeli_public_key, digital_signature, ppn):
        """
        Menambahkan faktur kedalam daftar faktur jika digital signature valid
        """
        faktur = OrderedDict({
            'pengusaha_public_key': pengusaha_public_key,
            'pembeli_public_key': pembeli_public_key,
            'ppn': ppn
        })

        # Membuat tanda penyimpanan blok pada node tertentu
        if pengusaha_public_key == pesan_mining:
            self.faktur_pajak.append(faktur)
            return len(self.chain) + 1
        else:
            # Daftar faktur yang ditambahkan dalam blok
            signature_verification = self.verifikasi_digital_signature(pengusaha_public_key, digital_signature, faktur)
            if signature_verification:
                self.faktur_pajak.append(faktur)
                return len(self.chain) + 1
            else:
                return False


# Memulai Blockchain
blockchain = Blockchain()

# Menggunakan Flask dan bertukar data dengan CORS
app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('tabel_blockchain.html')


@app.route('/konfigurasi')
def konfigurasi():
    return render_template('konfigurasi.html')


@app.route('/faktur-pajak/diterima', methods=['GET'])
def get_faktur():
    faktur_pajak = blockchain.faktur_pajak
    response = {'faktur_pajak': faktur_pajak}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'panjang_blok': len(blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/mining', methods=['GET'])
def mining():
    # Menjalankan algoritma proof of work
    nonce = blockchain.proof_of_work()

    blockchain.kirim_faktur(pengusaha_public_key=pesan_mining,
                                  pembeli_public_key=blockchain.node_id, # alamat node penyimpanan yang disamarkan
                                  digital_signature='',
                                  ppn='')

    blok_sebelumnya = blockchain.chain[-1]
    hash_sebelumnya = blockchain.hash(blok_sebelumnya)
    blok = blockchain.buat_block(nonce, hash_sebelumnya)

    response = {
        'message': 'Blok baru dibentuk',
        'nomor_blok': blok['nomor_blok'],
        'faktur_pajak': blok['faktur_pajak'],
        'nonce': blok['nonce'],
        'hash_sebelumnya': blok['hash_sebelumnya'],
    }
    return jsonify(response), 200


@app.route('/faktur/baru', methods=['POST'])
def post_faktur():
    values = request.form # mengambil dari form
    required = ['konfirmasi_pengusaha_public_key', 'konfirmasi_pembeli_public_key', 'digital_signature',
                'konfirmasi_ppn']
    if not all(k in values for k in required):
        return 'Terdapat value yang kurang', 400

    hasil_faktur = blockchain.kirim_faktur(values['konfirmasi_pengusaha_public_key'],
                                                        values['konfirmasi_pembeli_public_key'],
                                                        values['digital_signature'],
                                                        values['konfirmasi_ppn'])
    if hasil_faktur == False:
        response = {'message': 'Faktur/digital signature tidak valid'}
        return jsonify(response), 406
    else:
        response = {'message': 'Faktur baru akan ditambahkan pada blok ' + str(hasil_faktur)}
        return jsonify(response), 201


@app.route('/jaringan_blockchain', methods=['GET'])
def jaringan_blockchain():
    daftar_node = list(blockchain.nodes)
    response = {'nodes': daftar_node}
    return jsonify(response), 200


@app.route('/konsensus', methods=['GET'])
def konsensus():
    update_konsensus = blockchain.update_blok_terpanjang()

    if update_konsensus:
        response = {
            'message': 'Chain sudah di update',
            'chain_baru': blockchain.chain
        }
    else:
        response = {
            'message': 'Chain lebih panjang',
            'blockchain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/tambah_node', methods=['POST'])
def tambah_node():
    values = request.form
    # 127.0.0.1:5002,127.0.0.1:5003, 127.0.0.1:5004
    nodes = values.get('nodes').replace(' ', '').split(',')

    if nodes is None:
        return 'Error: Tolong tuliskan alamat node yang benar', 400

    for node in nodes:
        blockchain.tambah_node(node)

    response = {
        'message': 'Node sudah ditambahkan',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 200

# Menyalakan server
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
