from flask import Flask, request, jsonify, render_template

import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

import binascii
from collections import OrderedDict



class Faktur_Pajak:

    def __init__(self, pengusaha_public_key, pengusaha_private_key, pembeli_public_key, harga_jual):
        self.pengusaha_public_key = pengusaha_public_key
        self.pengusaha_private_key = pengusaha_private_key
        self.pembeli_public_key = pembeli_public_key
        self.harga_jual = harga_jual

    def daftar_faktur(self):
        return OrderedDict({
            'pengusaha_public_key': self.pengusaha_public_key,
            'pembeli_public_key': self.pembeli_public_key,
            'harga_jual': self.harga_jual,
        })

    def digital_signature(self):
        '''
        Menandatangani faktur dengan private key
        '''
        private_key = RSA.importKey(binascii.unhexlify(self.pengusaha_private_key))
        penandatanganan = PKCS1_v1_5.new(private_key)
        hash_daftar_faktur = SHA.new(str(self.daftar_faktur()).encode('utf8'))
        return binascii.hexlify(penandatanganan.sign(hash_daftar_faktur)).decode('ascii')

    def ppn_10(self):
        '''
        Menghitung PPN
        '''
        ppn_10 = float(self.harga_jual) * 0.1
        return ppn_10


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('buat_kunci.html')


@app.route('/buat_faktur', methods=['POST'])
def membuat_faktur():
    pengusaha_public_key = request.form['pengusaha_public_key']
    pengusaha_private_key = request.form['pengusaha_private_key']
    pembeli_public_key = request.form['pembeli_public_key']
    harga_jual = request.form['harga_jual']

    faktur_pajak = Faktur_Pajak(pengusaha_public_key, pengusaha_private_key, pembeli_public_key, harga_jual)

    response = {'transaction': faktur_pajak.daftar_faktur(),
                'ppn': faktur_pajak.ppn_10(),
                'digital_signature': faktur_pajak.digital_signature()}

    return jsonify(response), 200


@app.route('/ajukan/faktur')
def make_transaction():
    return render_template('buat_faktur.html')


@app.route('/lihat/faktur')
def view_transactions():
    return render_template('lihat_faktur.html')


@app.route('/buat_kunci')
def kunci_baru():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
