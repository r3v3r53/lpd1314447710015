import socket, time, random, struct
import select

class Scan:
    def __init__ (self, output, filename):
        self.output = output
        self.filename = ("report." + str(output), filename)[filename != None]

    def create_packet(self, id, icmp):
        header = struct.pack('bbHHh', icmp, 0, 0, id, 1)
        data = 192 * 'Q'
        my_checksum = self.checksum(header + data)
        header = struct.pack('bbHHh', icmp, 0,
                             socket.htons(my_checksum), id, 1)
        return header + data

    def receive_ping(self, my_socket, packet_id, time_sent, timeout):
        time_left = timeout
        while True:
            started_select = time.time()
            ready = select.select([my_socket], [], [], time_left)
            how_long_in_select = time.time() - started_select
            if ready[0] == []: # Timeout
                return
            time_received = time.time()
            rec_packet, addr = my_socket.recvfrom(1024)
            icmp_header = rec_packet[20:28]
            type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
            if p_id == packet_id:
                return time_received - time_sent
            time_left -= time_received - time_sent
            if time_left <= 0:
                return

    def checksum(self, source_string):
        sum = 0
        count_to = (len(source_string) / 2) * 2
        count = 0
        while count < count_to:
            this_val = ord(source_string[count + 1])*256+ord(source_string[count])
            sum = sum + this_val
            sum = sum & 0xffffffff # Necessary?
            count = count + 2
        if count_to < len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff # Necessary?
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer
