def main():
    ip = input("Digite o endereço IP (no formato xxx.xxx.xxx.xxx): ")
    
    if not validate_ip(ip):
        print("Endereço IP inválido.")
        return
    
    mask = input("Digite a máscara de subrede (no formato xxx.xxx.xxx.xxx): ")

    if not validate_mask(mask):
        print("Máscara de sub rede inválida.")
        return

    [network_address, cidr]= calc_network(ip, mask)
    broadcast_address = calc_broadcast(ip, cidr)
    hosts = num_of_hosts(cidr)
    ips = list_network_ips(network_address, hosts, cidr)


def validate_ip(ip):
    bytes = ip.split(".")

    if len(bytes) != 4:
        return False

    for byte in bytes:
        if len(byte) == 0:
            return False
        elif byte.isalpha():
            return False
        elif int(byte) not in range(0, 256):
            return False
        
    return True

def validate_mask(mask):
    bytes = mask.split(".")

    if len(bytes) != 4:
        return False

    bits = to_bin(bytes)

    zero_end = False
    for bit in bits:
        if bit == "1" and zero_end:
            return False
        elif bit == "0" and not zero_end:
            zero_end = True

    return True
        

def calc_network(ip, mask):
    ip_bytes = ip.split(".")
    mask_bytes = mask.split(".")

    cidr = 0

    for bit in to_bin(mask_bytes):
        if bit == "1":
            cidr += 1

    network_address = ""

    for i in range(4):
        network_address += str(int(ip_bytes[i]) & int(mask_bytes[i]))
        if i < 3:
            network_address += "."
    

    print(f"Endereço de sub rede: {network_address}/{cidr}")

    return [network_address, cidr]


def calc_broadcast(ip, cidr):
    ip_bytes = ip.split(".")

    ip_bits = to_bin(ip_bytes)

    broadcast_bits = ""
    broadcast_address = ""

    for i in range(cidr):
        broadcast_bits += ip_bits[i]
    
    for i in range(cidr, 32):
        broadcast_bits += "1"

    for i in range(0, len(broadcast_bits), 8):
        bits = broadcast_bits[i:i+8]
        broadcast_address += str(bin_to_decimal(bits))

        if i < len(broadcast_bits) - 8:
            broadcast_address += "."

    print(f"Endereço de broadcast da sub rede: {broadcast_address}")

    return broadcast_address


def num_of_hosts(cidr):
    hosts = 2 ** (32 - cidr) - 2

    print(f"A quantidade de hosts suportado é: {hosts}")

    return hosts

def list_network_ips(network_address, hosts, cidr):
    network_bytes = network_address.split(".")
    network_bin = to_bin(network_bytes)

    network_subnet_segment = network_bin[:cidr]

    print("Endereços IPv4 disponíveis para os hosts: ")

    for i in range (1, hosts + 1):
        available_ip_bin = network_subnet_segment

        available_ip_bin += to_bin([i], 32 - cidr)

        available_ip_address = ""

        for i in range(0, len(available_ip_bin), 8):
            available_ip_address += str(bin_to_decimal(available_ip_bin[i:i+8]))

            if i < len(available_ip_bin) - 8:
                available_ip_address += "."
        
        print(f"Endereço: {available_ip_address}")


def range_of_use(ip):
    pass

def to_bin(bytes, offset = 8):
    bits = ""

    for byte in bytes:
        byte_str = format(int(byte), "b")

        for i in range(offset - len(byte_str)):
            bits += "0"
        
        bits += format(int(byte), "b")

    return bits

def bin_to_decimal(bits):
    num = 0

    for i, bit in enumerate(reversed(bits)):
        num += int(bit) * (2 ** i)
    
    return num

if __name__ == "__main__":
    main()