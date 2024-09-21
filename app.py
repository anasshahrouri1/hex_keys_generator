import hashlib
import requests
from flask import Flask, render_template, request, redirect
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base58
import bech32
import random
from bitcoin import SelectParams

# Select Bitcoin mainnet parameters (assuming you are using bitcoin-python for something else)
SelectParams('mainnet')

app = Flask(__name__)

def ripemd160(x):
    """Perform RIPEMD160 hashing."""
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def create_wif(private_key, compressed=True):
    """Create WIF from a private key using Base58Check encoding."""
    key_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder='big')
    extended_key = b'\x80' + key_bytes
    if compressed:
        extended_key += b'\x01'

    # Double SHA256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]

    # Base58 encode the result
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    return wif

def generate_p2pkh_address(public_key_bytes):
    """Generate a P2PKH (Pay-to-PubKey-Hash) Bitcoin address."""
    sha256_pk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_pk = ripemd160(sha256_pk).digest()
    network_byte = b'\x00' + ripemd160_pk
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum).decode('utf-8')
    return address

def generate_p2pkh_compressed_address(private_key):
    """Generate P2PKH compressed address."""
    public_key = private_key.public_key()
    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    return generate_p2pkh_address(pubkey_bytes)

def generate_p2pkh_uncompressed_address(private_key):
    """Generate P2PKH uncompressed address."""
    public_key = private_key.public_key()
    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return generate_p2pkh_address(pubkey_bytes)

def generate_p2sh_address(public_key_bytes):
    """Generate a P2SH (Pay-to-Script-Hash) address embedding P2WPKH."""
    try:
        witness_program = ripemd160(hashlib.sha256(public_key_bytes).digest()).digest()
        redeem_script = b'\x00\x14' + witness_program  # OP_0 and push 20 bytes (P2WPKH)
        redeem_script_hash = ripemd160(hashlib.sha256(redeem_script).digest()).digest()
        network_byte = b'\x05' + redeem_script_hash
        checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
        p2sh_address = base58.b58encode(network_byte + checksum).decode('utf-8')
        return p2sh_address
    except Exception as e:
        print(f"Error generating P2SH address: {e}")
        return None

def generate_bech32_address(private_key):
    """Generate a Bech32 (P2WPKH) address using the compressed public key."""
    public_key = private_key.public_key()
    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    witness_program = ripemd160(hashlib.sha256(pubkey_bytes).digest()).digest()
    bech32_address = bech32.encode('bc', 0, witness_program)
    return bech32_address

def generate_addresses(hex_key):
    """Generate P2PKH compressed, P2PKH uncompressed, P2SH, and Bech32 addresses from a hex key."""
    try:
        private_key = ec.derive_private_key(int(hex_key, 16), ec.SECP256K1(), default_backend())
        wif_compressed = create_wif(private_key, compressed=True)
        wif_uncompressed = create_wif(private_key, compressed=False)
        p2pkh_compressed = generate_p2pkh_compressed_address(private_key)
        p2pkh_uncompressed = generate_p2pkh_uncompressed_address(private_key)
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        p2sh_address = generate_p2sh_address(public_key)
        bech32_address = generate_bech32_address(private_key)
        return {
            'wif_compressed': wif_compressed,
            'wif_uncompressed': wif_uncompressed,
            'p2pkh_compressed': p2pkh_compressed,
            'p2pkh_uncompressed': p2pkh_uncompressed,
            'p2sh_address': p2sh_address,
            'bech32_address': bech32_address
        }
    except Exception as e:
        print(f"Error generating addresses for key {hex_key}: {e}")
        return None

def get_balance(addresses):
    """Fetch balances for a list of addresses using blockchain.info."""
    addresses = [addr for addr in addresses if addr is not None]  # Filter out None addresses
    if not addresses:  # If no valid addresses remain, return empty balances
        return {}

    url = 'https://blockchain.info/balance?active=' + '|'.join(addresses)
    response = requests.get(url)
    
    if response.status_code == 200:
        balances = response.json()
        return {addr: {
            'final_balance': data['final_balance'] / 1e8,  # Current balance
            'tx_count': data['n_tx'],  # Transaction count
            'total_received': data['total_received'] / 1e8  # Total balance received
        } for addr, data in balances.items()}
    else:
        print(f"Error getting balance: {response.status_code}, Response: {response.text}")
        return {addr: {'final_balance': 0, 'tx_count': 0, 'total_received': 0} for addr in addresses}

@app.route('/keys/<int:page>')
def keys(page):
    """Generate and display keys and their balances."""
    max_key_value = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
    total_pages = max_key_value // 60 + 1  # +1 to ensure the last page includes the last key
    
    # Ensure we do not go past the total pages
    if page > total_pages:
        page = total_pages

    start_key = (page - 1) * 60
    end_key = min(start_key + 60 - 1, max_key_value)  # -1 to make the range inclusive

    keys_list = []
    p2pkh_compressed_addresses = []
    p2pkh_uncompressed_addresses = []
    p2sh_addresses = []
    bech32_addresses = []

    total_balance = 0
    total_received = 0
    total_tx = 0

    for i in range(start_key, end_key + 1):  # Inclusive range
        hex_key = f'{hex(i)[2:].zfill(64)}'

        key_info = generate_addresses(hex_key)
        if not key_info:
            print(f"Skipping key {hex_key} due to address generation error.")
            continue

        # Add to keys_list
        keys_list.append({
            'hex': hex_key,
            'wif_compressed': key_info['wif_compressed'],
            'wif_uncompressed': key_info['wif_uncompressed'],
            'p2pkh_compressed_address': key_info['p2pkh_compressed'],
            'p2pkh_uncompressed_address': key_info['p2pkh_uncompressed'],
            'p2sh_address': key_info['p2sh_address'],
            'bech32_address': key_info['bech32_address'],
        })

        p2pkh_compressed_addresses.append(key_info['p2pkh_compressed'])
        p2pkh_uncompressed_addresses.append(key_info['p2pkh_uncompressed'])
        if key_info['p2sh_address']:
            p2sh_addresses.append(key_info['p2sh_address'])
        bech32_addresses.append(key_info['bech32_address'])

    # Retrieve balances for each address type
    p2pkh_compressed_balances = get_balance(p2pkh_compressed_addresses)
    p2pkh_uncompressed_balances = get_balance(p2pkh_uncompressed_addresses)
    p2sh_balances = get_balance(p2sh_addresses)
    bech32_balances = get_balance(bech32_addresses)

    for key in keys_list:
        key['p2pkh_compressed_balance'] = p2pkh_compressed_balances.get(key['p2pkh_compressed_address'], {}).get('final_balance', 0)
        key['p2pkh_compressed_received'] = p2pkh_compressed_balances.get(key['p2pkh_compressed_address'], {}).get('total_received', 0)
        key['p2pkh_compressed_tx_count'] = p2pkh_compressed_balances.get(key['p2pkh_compressed_address'], {}).get('tx_count', 0)

        key['p2pkh_uncompressed_balance'] = p2pkh_uncompressed_balances.get(key['p2pkh_uncompressed_address'], {}).get('final_balance', 0)
        key['p2pkh_uncompressed_received'] = p2pkh_uncompressed_balances.get(key['p2pkh_uncompressed_address'], {}).get('total_received', 0)
        key['p2pkh_uncompressed_tx_count'] = p2pkh_uncompressed_balances.get(key['p2pkh_uncompressed_address'], {}).get('tx_count', 0)

        key['p2sh_balance'] = p2sh_balances.get(key['p2sh_address'], {}).get('final_balance', 0)
        key['p2sh_received'] = p2sh_balances.get(key['p2sh_address'], {}).get('total_received', 0)
        key['p2sh_tx_count'] = p2sh_balances.get(key['p2sh_address'], {}).get('tx_count', 0)

        key['bech32_balance'] = bech32_balances.get(key['bech32_address'], {}).get('final_balance', 0)
        key['bech32_received'] = bech32_balances.get(key['bech32_address'], {}).get('total_received', 0)
        key['bech32_tx_count'] = bech32_balances.get(key['bech32_address'], {}).get('tx_count', 0)

        # Add to total balance
        total_balance += key['p2pkh_compressed_balance'] + key['p2pkh_uncompressed_balance'] + key['p2sh_balance'] + key['bech32_balance']
        total_received += key['p2pkh_compressed_received'] + key['p2pkh_uncompressed_received'] + key['p2sh_received'] + key['bech32_received']
        total_tx += key['p2pkh_compressed_tx_count'] + key['p2pkh_uncompressed_tx_count'] + key['p2sh_tx_count'] + key['bech32_tx_count']

    return render_template('keys.html', keys=keys_list, page=page, total_balance=total_balance, total_received=total_received, total_tx=total_tx, total_pages=total_pages)


@app.route('/keys/random')
def random_keys():
    """Redirect to a random page of keys."""
    total_pages = 1929868153955269923726183083478131797547292737984581739710086052358636024906  # Adjust based on total number of pages
    random_page = random.randint(1, total_pages)
    return redirect(f'/keys/{random_page}')


@app.route('/search')
def search():
    """Search for a key and redirect to the appropriate page."""
    query = request.args.get('query', '').strip()

    if not query:
        return redirect('/')  # Redirect to home if no query is provided

    # Try to handle as WIF or HEX
    try:
        if query.startswith('5') or query.startswith('K') or query.startswith('L'):  # WIF starts with '5', 'K', or 'L'
            # Handle WIF input
            hex_key = wif_to_hex(query)
        else:
            # Assume it's a HEX input
            hex_key = query
    except Exception as e:
        return f"Invalid key: {str(e)}"

    # Calculate the page number (each page contains 60 keys)
    try:
        decimal_value = int(hex_key, 16)

        # The correct max value for the last key (max private key)
        max_key_value = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
        total_pages = max_key_value // 60

        # Calculate the page for the given key
        page = (decimal_value // 60) + 1

        # Ensure the page does not exceed the last valid page
        if page > total_pages:
            page = total_pages  # Redirect to the last valid page

    except ValueError:
        return "Invalid HEX key"

    # Redirect to the appropriate page
    return redirect(f'/keys/{page}')


def wif_to_hex(wif):
    """Convert a WIF private key back to a HEX private key."""
    try:
        decoded = base58.b58decode(wif)
    except Exception as e:
        raise ValueError(f"Failed to decode WIF: {str(e)}")

    # Check for valid length (compressed or uncompressed WIF)
    print(f"Decoded WIF length: {len(decoded)}")

    if len(decoded) == 38:  # Compressed WIF
        private_key = decoded[1:-5]  # Remove version byte, compression flag, and checksum
    elif len(decoded) == 37:  # Uncompressed WIF
        private_key = decoded[1:-4]  # Remove version byte and checksum
    else:
        raise ValueError(f"Invalid WIF length: {len(decoded)}")

    # Verify checksum
    checksum = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4]
    if checksum != decoded[-4:]:
        raise ValueError("Invalid WIF checksum")

    # Convert to hexadecimal format
    return private_key.hex()


if __name__ == '__main__':
    app.run(debug=True)
