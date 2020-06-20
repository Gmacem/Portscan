import argparse
import socket
import threading


timeout = 0.5
threadcount = 20


def ntp_message():
    msg = '\x1b' + 47 * '\0'
    return msg.encode('utf-8')


def scan_tcp_port(ip, port, opened):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        conn = sock.connect((ip, port))
        opened.append(port)
    except:
        pass

    sock.close()


def scan_udp_port(ip, port, opened):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(ntp_message(), (ip, port))
        data = sock.recvfrom(1024)
        opened.append(port)
    except Exception as ex:
        pass
    sock.close()


def split_port_list(ports):
    block_size = (len(ports) + threadcount - 1) // threadcount
    for i in range(0, len(ports), block_size):
        yield ports[i:min(len(ports), i + block_size)]


def scan_range(args, ports, opened_tcp, opened_udp):
    for port in ports:
        if args.tcp:
            scan_tcp_port(args.ip, port, opened_tcp)

        if args.udp:
            scan_udp_port(args.ip, port, opened_udp)


def main(args):
    threads = []
    opened_tcp = []
    opened_udp = []
    chunks = list(split_port_list(range(*map(int, args.ports))))
    for chunk in chunks:
        threads.append(threading.Thread(target=scan_range,
                                        args=(args, chunk,
                                              opened_tcp, opened_udp)))
        threads[-1].start()

    for thread in threads:
        thread.join()

    opened_tcp.sort()
    opened_udp.sort()
    if args.tcp:
        for port in opened_tcp:
            print("TCP {}".format(port))
    if args.udp:
        for port in opened_udp:
            print("UDP {}".format(port))


def init_parser():
    parser = argparse.ArgumentParser(description='Portscan')
    parser.add_argument('-i', '--ip', help='ip address', default="127.0.0.1")
    parser.add_argument('-t', '--tcp', help='list of open TCP ports',
                        action='store_true')
    parser.add_argument('-u', '--udp', help='list of open UDP ports',
                        action='store_true')
    parser.add_argument('-p', '--ports', nargs=2, help='ports range',
                        metavar=('begin', 'end'), default=[0, 100])

    return parser


if __name__ == "__main__":
    parser = init_parser()
    main(parser.parse_args())
