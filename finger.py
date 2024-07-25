import ubluetooth
import time
from micropython import const
import hashlib
from struct import pack, unpack
from binascii import hexlify, unhexlify
import os
import ucryptolib

_IRQ_CENTRAL_CONNECT = const(1)
_IRQ_CENTRAL_DISCONNECT = const(2)
_IRQ_GATTS_WRITE = const(3)
_IRQ_GATTS_READ_REQUEST = const(4)
_IRQ_SCAN_RESULT = const(5)
_IRQ_SCAN_DONE = const(6)
_IRQ_PERIPHERAL_CONNECT = const(7)
_IRQ_PERIPHERAL_DISCONNECT = const(8)
_IRQ_GATTC_SERVICE_RESULT = const(9)
_IRQ_GATTC_SERVICE_DONE = const(10)
_IRQ_GATTC_CHARACTERISTIC_RESULT = const(11)
_IRQ_GATTC_CHARACTERISTIC_DONE = const(12)
_IRQ_GATTC_DESCRIPTOR_RESULT = const(13)
_IRQ_GATTC_DESCRIPTOR_DONE = const(14)
_IRQ_GATTC_READ_RESULT = const(15)
_IRQ_GATTC_READ_DONE = const(16)
_IRQ_GATTC_WRITE_DONE = const(17)
_IRQ_GATTC_NOTIFY = const(18)
_IRQ_GATTC_INDICATE = const(19)

class Coder:
    FUN_SENDER_DEVICE_INFO = const(0)
    FUN_SENDER_PAIR = const(1)
    FUN_SENDER_DPS = const(2)
    FUN_SENDER_DEVICE_STATUS = const(3)
    FUN_RECEIVE_TIME1_REQ = const(32785)
    FUN_RECEIVE_DP = const(32769)

class DpType:
    RAW = const(0)
    BOOLEAN = const(1)
    INT = const(2)
    STRING = const(3)
    ENUM = const(4)

class DpAction:
    ARM_DOWN_PERCENT = const(6)
    ARM_UP_PERCENT = const(5)
    CLICK_SUSTAIN_TIME = const(3)
    TAP_ENABLE = const(17)
    MODE = const(2)
    INVERT_SWITCH = const(4)
    TOGGLE_SWITCH = const(1)
    CLICK = const(101)
    PROG = const(121)

class SecretKeyManager:
    def __init__(self, login_key):
        self.login_key = login_key
        print(f"Initializing SecretKeyManager with login_key: {self.login_key}")
        self.keys = {4: hashlib.md5(self.login_key).digest()}
        print(f"MD5 hash for security flag 4: {hexlify(self.keys[4])}")

    def get(self, security_flag):
        key = self.keys.get(security_flag, None)
        print(f"Retrieving key for security_flag {security_flag}: {hexlify(key) if key else 'None'}")
        return key

    def setSrand(self, srand):
        self.keys[5] = hashlib.md5(self.login_key + srand).digest()
        print(f"Setting srand: {srand}, new MD5 hash for security flag 5: {hexlify(self.keys[5])}")

class DeviceInfoResp:
    def __init__(self):
        self.success = False

    def parse(self, raw):
        print(f"Parsing DeviceInfoResp: {hexlify(raw)}")
        device_version_major, device_version_minor, protocol_version_major, protocol_version_minor, flag, is_bind, srand, hardware_version_major, hardware_version_minor, auth_key = unpack('>BBBBBB6sBB32s', raw[:46])
        auth_key = hexlify(auth_key)
        print(f"Device Info Parsed: Device Version: {device_version_major}.{device_version_minor}, Protocol Version: {protocol_version_major}.{protocol_version_minor}, Flag: {flag}, Is Bind: {is_bind}, Srand: {hexlify(srand)}, Hardware Version: {hardware_version_major}.{hardware_version_minor}, Auth Key: {auth_key}")

        self.device_version = '{}.{}'.format(device_version_major, device_version_minor)
        self.protocol_version = '{}.{}'.format(protocol_version_major, protocol_version_minor)
        self.flag = flag
        self.is_bind = is_bind
        self.srand = srand
        self.hardware_version = '{}.{}'.format(hardware_version_major, hardware_version_minor)

        protocol_number = protocol_version_major * 10 + protocol_version_minor
        if protocol_number < 20:
            self.success = False
            return

        self.success = True
        return

class Ret:
    def __init__(self, raw, version):
        self.raw = raw
        self.version = version

    def parse(self, secret_key):
        print(f"Parsing Ret: {hexlify(self.raw)}, Version: {self.version}")
        self.security_flag = self.raw[0]
        self.iv = self.raw[1:17]
        encrypted_data = self.raw[17:]
        decrypted_data = AesUtils.decrypt(encrypted_data, self.iv, secret_key)
        print(f"Decrypted Data: {hexlify(decrypted_data)}")

        sn, sn_ack, code, length = unpack('>IIHH', decrypted_data[:12])
        raw_data = decrypted_data[12:12 + length]
        print(f"SN: {sn}, SN_ACK: {sn_ack}, Code: {code}, Length: {length}, Raw Data: {hexlify(raw_data)}")

        self.resp = None
        try:
            self.code = code
        except Exception:
            self.code = code

        if self.code == Coder.FUN_SENDER_DEVICE_INFO:
            resp = DeviceInfoResp()
            resp.parse(raw_data)
            self.resp = resp

class BleReceiver:
    def __init__(self, secret_key_manager):
        self.last_index = 0
        self.data_length = 0
        self.current_length = 0
        self.raw = bytearray()
        self.version = 0

        self.secret_key_manager = secret_key_manager

    def unpack(self, arr):
        i = 0
        packet_number = 0
        while i < 4 and i < len(arr):
            b = arr[i]
            packet_number |= (b & 255) << (i * 7)
            if ((b >> 7) & 1) == 0:
                break
            i += 1

        pos = i + 1
        if packet_number == 0:
            self.data_length = 0

            while (pos <= i + 4 and pos < len(arr)):
                b2 = arr[pos]
                self.data_length |= (b2 & 255) << (((pos - 1) - i) * 7)
                if (((b2 >> 7) & 1) == 0):
                    break
                pos += 1

            self.current_length = 0
            self.last_index = 0
            if (pos == i + 5 or len(arr) < pos + 2):
                return 2

            self.raw[:] = b''  # Clear the bytearray
            pos += 1
            self.version = (arr[pos] >> 4) & 15
            pos += 1

        if (packet_number == 0 or packet_number > self.last_index):
            data = bytearray(arr[pos:])
            self.current_length += len(data)
            self.last_index = packet_number
            self.raw += data

            if self.current_length < self.data_length:
                return 1

            return 0 if self.current_length == self.data_length else 3

    def parse_data_received(self, arr):
        status = self.unpack(arr)
        print(f"Unpack status: {status}, Raw Data: {hexlify(self.raw)}")
        if status == 0:
            security_flag = self.raw[0]
            secret_key = self.secret_key_manager.get(security_flag)

            ret = Ret(self.raw, self.version)
            ret.parse(secret_key)

            return ret

        return None

class AesUtils:
    @staticmethod
    def decrypt(data, iv, key):
        print(f"Decrypting data: {hexlify(data)} with IV: {hexlify(iv)} and key: {hexlify(key)}")
        cipher = ucryptolib.aes(key, 2, iv)
        decrypted = cipher.decrypt(data)
        print(f"Decrypted data: {hexlify(decrypted)}")
        return decrypted

    @staticmethod
    def encrypt(data, iv, key):
        print(f"Encrypting data: {hexlify(data)} with IV: {hexlify(iv)} and key: {hexlify(key)}")
        cipher = ucryptolib.aes(key, 2, iv)
        encrypted = cipher.encrypt(data)
        print(f"Encrypted data: {hexlify(encrypted)}")
        return encrypted

class CrcUtils:
    @staticmethod
    def crc16(data):
        crc = 0xFFFF
        for byte in data:
            crc ^= byte & 255
            for _ in range(8):
                tmp = crc & 1
                crc >>= 1
                if tmp != 0:
                    crc ^= 0xA001

        return crc

class TuyaDataPacket:
    @staticmethod
    def prepare_crc(sn_ack, ack_sn, code, inp, inp_length):
        raw = pack('>IIHH', sn_ack, ack_sn, code, inp_length)
        raw += inp
        crc = CrcUtils.crc16(raw)
        print(f"Prepared CRC: {crc}")
        return raw + pack('>H', crc)

    @staticmethod
    def get_random_iv():
        iv = os.urandom(16)
        print(f"Generated random IV: {hexlify(iv)}")
        return iv

    @staticmethod
    def encrypt_packet(secret_key, security_flag, iv, data):
        while len(data) % 16 != 0:
            data += b'\x00'

        encrypted_data = AesUtils.encrypt(data, iv, secret_key)
        output = bytearray()
        output += bytes([security_flag])
        output += iv
        output += encrypted_data

        print(f"Encrypted packet: {hexlify(output)}")
        return output

class XRequest:
    def __init__(self, sn_ack, ack_sn, code, security_flag, secret_key, iv, inp):
        self.gatt_mtu = 20
        self.sn_ack = sn_ack
        self.ack_sn = ack_sn
        self.code = code
        self.security_flag = security_flag
        self.secret_key = secret_key
        self.iv = iv
        self.inp = inp

    def split_packet(self, protocol_version, data):
        output = []
        packet_number = 0
        pos = 0
        length = len(data)
        while pos < length:
            b = bytearray()
            b += bytes([packet_number])

            if packet_number == 0:
                b += pack('>B', length)
                b += pack('<B', protocol_version << 4)

            sub_data = data[pos:pos + self.gatt_mtu - len(b)]
            b += sub_data
            output.append(b)

            pos += len(sub_data)
            packet_number += 1

        print(f"Split packets: {[hexlify(p) for p in output]}")
        return output

    def pack(self):
        data = TuyaDataPacket.prepare_crc(self.sn_ack, self.ack_sn, self.code, self.inp, len(self.inp))
        encrypted_data = TuyaDataPacket.encrypt_packet(self.secret_key, self.security_flag, self.iv, data)
        return self.split_packet(2, encrypted_data)

class FingerBot:
    SERVICE_UUID = ubluetooth.UUID(0x1910)
    NOTIFY_CHAR_UUID = ubluetooth.UUID(0x2b10)
    WRITE_CHAR_UUID = ubluetooth.UUID(0x2b11)

    def __init__(self, mac, local_key, uuid, dev_id, fixed_iv=""):
        self.mac = mac.lower()
        self.uuid = uuid.encode('utf-8')
        self.dev_id = dev_id.encode('utf-8')
        self.login_key = local_key[:6].encode('utf-8')
        self.fixed_iv = unhexlify(fixed_iv) if fixed_iv and len(fixed_iv) == 32 else None
        self.secret_key_manager = SecretKeyManager(self.login_key)
        self.ble_receiver = BleReceiver(self.secret_key_manager)
        self.reset_sn_ack()
        self.ble = ubluetooth.BLE()
        self.ble.active(True)
        self.ble.irq(self.ble_irq)
        self.conn_handle = None
        self.notify_handle = None
        self.write_handle = None
        self.initial_read_event_handled = False
        self.service_start_handle = None
        self.service_end_handle = None
        self.pairing_complete = False

    def ble_irq(self, event, data):
        print(f"BLE event: {event}, data: {data}")
        if event == _IRQ_PERIPHERAL_CONNECT:
            self.conn_handle, _, _ = data
            print(f"Connected to device, conn_handle: {self.conn_handle}")
            self.ble.gattc_discover_services(self.conn_handle)
        elif event == _IRQ_PERIPHERAL_DISCONNECT:
            self.conn_handle = None
            print("Disconnected from device")
        elif event == _IRQ_GATTC_SERVICE_RESULT:
            conn_handle, start_handle, end_handle, uuid = data
            print(f"Service found: UUID({uuid}), conn_handle: {conn_handle}")
            if uuid == self.SERVICE_UUID:
                print(f"Comparing UUID({uuid}) with expected UUID({self.SERVICE_UUID})")
                if uuid == self.SERVICE_UUID:
                    print("Matched service UUID")
                    self.service_start_handle = start_handle
                    self.service_end_handle = end_handle
        elif event == _IRQ_GATTC_SERVICE_DONE:
            print(f"Service discovery complete. Service handles: start={self.service_start_handle}, end={self.service_end_handle}, conn_handle={self.conn_handle}")
            if self.service_start_handle and self.service_end_handle:
                self.ble.gattc_discover_characteristics(self.conn_handle, self.service_start_handle, self.service_end_handle)
        elif event == _IRQ_GATTC_CHARACTERISTIC_RESULT:
            conn_handle, def_handle, value_handle, properties, uuid = data
            print(f"Characteristic found: UUID({uuid}), conn_handle: {conn_handle}")
            if uuid == self.NOTIFY_CHAR_UUID:
                self.notify_handle = value_handle
                print(f"Notification characteristic found, notify_handle: {self.notify_handle}")
            elif uuid == self.WRITE_CHAR_UUID:
                self.write_handle = value_handle
                print(f"Write characteristic found, write_handle: {self.write_handle}")
        elif event == _IRQ_GATTC_CHARACTERISTIC_DONE:
            print(f"Characteristic discovery complete. Notify handle: {self.notify_handle}, Write handle: {self.write_handle}, conn_handle: {self.conn_handle}")
            if self.notify_handle is not None and self.write_handle is not None:
                self.subscribe_notifications()
                req = self.device_info_request()
                self.send_request(req)
        elif event == _IRQ_GATTC_NOTIFY:
            conn_handle, value_handle, notify_data = data
            print(f"Notification received: {hexlify(notify_data)}, conn_handle: {conn_handle}, notify_handle: {value_handle}")
            self.handle_notification(bytes(notify_data))
        elif event == _IRQ_GATTC_INDICATE:
            conn_handle, value_handle, status = data
            print(f"Indicate result received, status: {status}")
        elif event == _IRQ_GATTC_READ_RESULT:
            conn_handle, value_handle, char_data = data
            print(f"Read result received: {char_data}")
            if not self.initial_read_event_handled:
                self.initial_read_event_handled = True
                if self.notify_handle is not None and self.write_handle is not None:
                    self.subscribe_notifications()
                    req = self.device_info_request()
                    self.send_request(req)
            self.handle_notification(bytes(char_data))
        elif event == _IRQ_GATTC_WRITE_DONE:
            conn_handle, value_handle, status = data
            print(f"Write result received, status: {status}, conn_handle: {conn_handle}")

    def connect(self):
        print("Connecting...")
        self.ble.gap_connect(0, bytes.fromhex(self.mac.replace(':', '')))

    def subscribe_notifications(self):
        if self.conn_handle is not None and self.notify_handle is not None:
            self.ble.gattc_write(self.conn_handle, self.notify_handle + 1, b'\x01\x00', 1)
            print(f"Subscribed to notifications, conn_handle: {self.conn_handle}, notify_handle: {self.notify_handle}")
        else:
            print(f"Not subscribed to notifications, conn_handle: {self.conn_handle}, notify_handle: {self.notify_handle}")

    def write_char(self, data):
        if self.conn_handle is not None and self.write_handle is not None:
            self.ble.gattc_write(self.conn_handle, self.write_handle, data, 0)
            print(f"Written to characteristic (WriteWithoutResponse), conn_handle: {self.conn_handle}, write_handle: {self.write_handle}")
        else:
            print(f"Not written, conn_handle: {self.conn_handle}, write_handle: {self.write_handle}")

    def next_sn_ack(self):
        self.sn_ack += 1
        return self.sn_ack

    def reset_sn_ack(self):
        self.sn_ack = 0

    def handle_notification(self, value):
        print(f'<< NOTIFICATION (incoming): {hexlify(value)}')
        ret = self.ble_receiver.parse_data_received(value)
        if not ret:
            print("Error processing notification")
            return

        if ret.code == Coder.FUN_SENDER_DEVICE_INFO:
            self.secret_key_manager.setSrand(ret.resp.srand)
            print('Pairing...')
            req = self.pair_request()
            self.send_request(req)
        elif ret.code == Coder.FUN_SENDER_PAIR:
            self.pairing_complete = True

    def send_request(self, xrequest):
        packets = xrequest.pack()
        for cmd in packets:
            print(f'>> REQUEST (outgoing): {hexlify(cmd)}')
            self.write_char(cmd)
            time.sleep(0.1)

    def device_info_request(self):
        inp = bytearray(0)
        iv = self.fixed_iv if self.fixed_iv else TuyaDataPacket.get_random_iv()
        security_flag = 4
        secret_key = self.secret_key_manager.get(security_flag)
        sn_ack = self.next_sn_ack()
        return XRequest(sn_ack, 0, Coder.FUN_SENDER_DEVICE_INFO, security_flag, secret_key, iv, inp)

    def pair_request(self):
        security_flag = 5
        secret_key = self.secret_key_manager.get(security_flag)
        iv = self.fixed_iv if self.fixed_iv else TuyaDataPacket.get_random_iv()
        inp = bytearray()
        inp += self.uuid
        inp += self.login_key
        inp += self.dev_id

        for _ in range(22 - len(self.dev_id)):
            inp += b'\x00'

        sn_ack = self.next_sn_ack()
        return XRequest(sn_ack, 0, Coder.FUN_SENDER_PAIR, security_flag, secret_key, iv, inp)

    def send_dps(self, dps):
        security_flag = 5
        secret_key = self.secret_key_manager.get(security_flag)
        iv = self.fixed_iv if self.fixed_iv else TuyaDataPacket.get_random_iv()
        if not dps:
            dps = [
                [2, DpType.ENUM, 0],
                [DpAction.ARM_DOWN_PERCENT, DpType.INT, 100],
                [DpAction.ARM_UP_PERCENT, DpType.INT, 0],
                [DpAction.CLICK_SUSTAIN_TIME, DpType.INT, 1],
                [DpAction.CLICK, DpType.BOOLEAN, True],
            ]
        raw = b''
        for dp in dps:
            dp_id, dp_type, dp_value = dp
            raw += pack('>BB', dp_id, dp_type)
            if dp_type == DpType.BOOLEAN:
                length = 1
                val = 1 if dp_value else 0
                raw += pack('>BB', length, val)
            elif dp_type == DpType.INT:
                length = 4
                raw += pack('>BI', length, dp_value)
            elif dp_type == DpType.STRING:
                length = len(dp_value)
                raw += pack('>B', length) + dp_value.encode('utf-8')
            elif dp_type == DpType.ENUM:
                length = 1
                raw += pack('>BB', length, dp_value)

        print(f"DPS raw data: {hexlify(raw)}")
        sn_ack = self.next_sn_ack()
        return XRequest(sn_ack, 0, Coder.FUN_SENDER_DPS, security_flag, secret_key, iv, raw)

finger_bot = FingerBot("XX:XX:XX:XX:XX:XX", "LOCAL_KEY", "UUID", "DEV_ID")

finger_bot.connect()

while True:
    if finger_bot.pairing_complete:
        req = finger_bot.send_dps([])
        finger_bot.send_request(req)
    print(" ")
    time.sleep(10)