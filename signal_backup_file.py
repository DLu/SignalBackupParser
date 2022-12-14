import collections
import hashlib
import hmac
import io
import os
import re

from Backups_pb2 import BackupFrame
from Reactions_pb2 import ReactionList

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util import strxor

from axolotl.kdf.hkdfv3 import HKDFv3

import click


class FrameReader:
    def __init__(self, filename, password):
        self.file = io.open(filename, 'rb', buffering=1024 * 1024)
        self.bytes_read = 0
        self.bytes_total = os.path.getsize(filename)

        header_length = int.from_bytes(self.read(4), byteorder='big')
        header_frame = self.read(header_length)
        frame = BackupFrame()
        frame.ParseFromString(header_frame)

        # Backup Key
        b_password = password.encode()
        digest = SHA512.new()
        digest.update(frame.header.salt)
        hsh = b_password
        for i in range(250000):
            digest.update(hsh)
            digest.update(b_password)
            hsh = digest.digest()
            digest = SHA512.new()
        key = hsh[:32]

        derivative = HKDFv3().deriveSecrets(key, b'Backup Export', 64)
        self.cipher_key = derivative[:32]
        self.mac_key = derivative[32:]
        self.iv = bytearray(frame.header.iv)
        self.counter = int.from_bytes(self.iv[:4], byteorder='big')
        self.aes_cipher = AES.new(self.cipher_key, AES.MODE_ECB)

    def read(self, length):
        self.bytes_read += length
        return self.file.read(length)

    def read_frame(self, length, with_iv=False):
        val = int.to_bytes(self.counter, length=16, byteorder='little')
        self.iv[3] = val[0]
        self.iv[2] = val[1]
        self.iv[1] = val[2]
        self.iv[0] = val[3]
        self.counter += 1
        mac = hmac.new(self.mac_key, digestmod=hashlib.sha256)
        enc_iv = self.iv
        if with_iv:
            mac.update(self.iv)
        ofile = io.BytesIO()

        def get_chunk():
            # Read as many 16 byte chunks as possible
            for i in range(int(length / 16)):
                yield self.read(16)
            # Read remainder
            yield self.read(length % 16)

        for enc_chunk in get_chunk():
            mac.update(enc_chunk)
            output = strxor.strxor(
                enc_chunk,
                self.aes_cipher.encrypt(enc_iv)[:len(enc_chunk)]
            )
            ctr = int.from_bytes(enc_iv, byteorder='big') + 1
            enc_iv = int.to_bytes(ctr, length=16, byteorder='big')
            ofile.write(output)

        our_mac = mac.digest()
        our_mac = our_mac[:10]  # trim to 1st 10 bytes
        their_asset_mac = self.read(10)
        assert hmac.compare_digest(our_mac, their_asset_mac)
        return ofile.getvalue()

    def __iter__(self):
        last_bytes = 0
        with click.progressbar(length=self.bytes_total) as bar:
            while self.bytes_read < self.bytes_total:
                # Read Frame
                frame_length = int.from_bytes(self.read(4), byteorder='big')
                frame = BackupFrame()
                frame.ParseFromString(self.read_frame(frame_length - 10))

                # Read Attachment
                attachment = None
                attachment_length = frame.attachment.length or frame.avatar.length or frame.sticker.length
                if attachment_length:
                    attachment = self.read_frame(attachment_length, with_iv=True)
                yield frame, attachment
                bar.update(self.bytes_read - last_bytes)
                last_bytes = self.bytes_read


class DictReader:
    def __init__(self, filename, password):
        self.frame_reader = FrameReader(filename, password)
        self.datatypes = {}

    def _get_table_definition(self, statement):
        create_pattern = re.compile(r'CREATE TABLE "?(\w+)"?\s*\((.*)\)', re.DOTALL)
        m = create_pattern.match(statement)
        if not m:
            click.secho(f'Bad table definition {statement}', fg='yellow')
            return None, None
        fields = []
        for field in m.group(2).split(','):
            parts = field.strip().split()
            name = parts.pop(0)
            if not parts:
                fields.append((name, None))
            elif parts[0] == 'INTEGER':
                fields.append((name, int))
            elif parts[0] == 'TEXT':
                fields.append((name, str))
            elif parts[0] == 'BLOB':
                fields.append((name, 'blob'))
            elif parts[0] == 'REAL':
                fields.append((name, float))
            elif parts == ['DEFAULT', 'NULL']:
                fields.append((name, None))
            elif parts == ['DEFAULT', '0']:
                fields.append((name, int))
        return m.group(1), fields

    def _get_insertion(self, frame):
        insert_pattern = re.compile(r'INSERT INTO (\w+) ')
        m = insert_pattern.match(frame.statement.statement)
        table = m.group(1)
        parameters = []
        for parameter in frame.statement.parameters:
            ptype, _, value = str(parameter).partition(': ')
            if value[-1] == '\n':
                value = value[:-1]
            if ptype == 'nullparameter' and value.strip() == 'true':
                parameters.append(None)
            elif ptype == 'blobParameter':
                parameters.append(eval('b' + value))
            elif ptype == 'stringParamter':  # Yes, parameter is misspelled
                s = eval('b' + value).decode()
                parameters.append(s)
            else:
                parameters.append(eval(value))

        return table, parameters

    def __iter__(self):
        for frame, att in self.frame_reader:
            if frame.statement.statement:
                statement = frame.statement.statement
                if 'CREATE ' in statement:
                    if 'sqlite' in statement:
                        continue
                    if 'CREATE VIRTUAL TABLE' in statement or 'CREATE INDEX' in statement:
                        continue
                    if 'CREATE UNIQUE INDEX' in statement or 'CREATE TRIGGER' in statement:
                        continue
                    table, fields = self._get_table_definition(statement)
                    if table:
                        self.datatypes[table] = fields
                    else:
                        click.secho(statement, fg='yellow')
                        exit(0)
                elif 'INSERT INTO ' in statement:
                    table, parameters = self._get_insertion(frame)
                    entry = {}
                    for (name, dt), value in zip(self.datatypes[table], parameters):
                        if value is None:
                            continue
                        entry[name] = value
                    yield table, entry
                else:
                    click.secho(f'Unmatched statement {statement}', fg='yellow')
                    exit(1)
            elif frame.version.version:
                yield 'version', frame.version.version
            elif frame.attachment:
                entry = {'attachmentId': frame.attachment.attachmentId, 'rowId': frame.attachment.rowId,
                         'data': att}
                yield 'attachment', entry
            else:
                click.secho(f'Unmatched frame type {frame}', fg='red')
                exit(1)


# Base Types as defined here:
# https://github.com/signalapp/Signal-Android/blob/ec1f771364633b5156e198ba6ff780b68307746b/
#     app/src/main/java/org/thoughtcrime/securesms/database/MmsSmsColumns.java#L66-L94
MESSAGE_TYPES = [
    # 0-5
    '', 'incoming audio call', 'outgoing audio call', 'missed audio call', 'joined', 'unsupported message',
    # 6-10
    'invalid message', 'profile change', 'missed video call', 'gv1 migration', 'incoming video call',
    # 11-15
    'outgoing video call', 'group call', 'bad decrypt', 'change number', 'boost request',
    # 16-20
    'thread merge', 'sms export', '', '', 'inbox',
    # 21-25
    'outbox', 'sending', 'sent', 'sent failed', 'pending secure sms fallback',
    # 26-27
    'pending insecure sms fallback', 'draft type']
MESSAGE_TYPE_MASK = 0x1F


class ThreadReader:
    def __init__(self, filename, password):
        self.recipients = {}
        thread_mapping = {}
        self.threads = collections.defaultdict(list)
        attachments = {}
        messages_by_id = {}
        groups = []
        reactions = []

        for table, entry in DictReader(filename, password):
            if table == 'recipient':
                if 'group_id' in entry:
                    continue
                for key in ['system_display_name', 'profile_joined_name', 'signal_profile_name']:
                    if entry.get(key):
                        name = entry[key]
                        break
                else:
                    # No name found, ignore
                    continue
                self.recipients[entry['_id']] = {'name': name, 'phone': entry.get('phone', '')}
            elif table == 'groups':
                groups.append(entry)
            elif table == 'thread':
                thread_mapping[entry['_id']] = entry['thread_recipient_id']
            elif table in ['sms', 'mms']:
                msg = {'date': entry['date']}
                if entry.get('server_guid') is None:
                    msg['address'] = 1
                else:
                    msg['address'] = entry['address']
                if 'body' in entry:
                    msg['body'] = entry['body']

                if 'type' in entry:
                    base_type = entry['type'] & MESSAGE_TYPE_MASK
                    msg['type'] = MESSAGE_TYPES[base_type]

                recipient_id = thread_mapping[entry['thread_id']]
                self.threads[recipient_id].append(msg)
                messages_by_id[entry['_id']] = msg

                if 'reactions' in entry:
                    r = ReactionList()
                    r.ParseFromString(entry['reactions'])
                    for a in r.reactions:
                        reaction = {
                            'mid': entry['_id'],
                            'emoji': a.emoji,
                            'date': a.sentTime,
                            'aid': a.author,
                        }
                        reactions.append(reaction)
            elif table == 'part':
                attachments[entry['_id']] = {'type': entry['ct'],
                                             'unique_id': entry['unique_id'],
                                             'mid': entry['mid']
                                             }
            elif table == 'attachment':
                if entry['rowId'] not in attachments:
                    continue
                attachments[entry['rowId']]['data'] = entry['data']
                assert attachments[entry['rowId']]['unique_id'] == entry['attachmentId']
            elif table == 'reaction':
                reaction = {
                    'mid': entry['message_id'],
                    'emoji': entry['emoji'],
                    'date': entry['date_sent'],
                    'aid': entry['author_id'],
                }
                reactions.append(reaction)

        for entry in groups:
            group = {'name': entry['title'], 'members': [], 'group_id': entry['group_id']}
            for member in entry['members'].split(','):
                mid = int(member)
                group['members'].append(dict(self.recipients[mid]))
            self.recipients[entry['recipient_id']] = group

        for thread in self.threads.values():
            for msg in thread:
                address = msg.pop('address')
                msg['author'] = self.recipients[address]

        for attachment in attachments.values():
            mid = attachment.pop('mid')
            msg = messages_by_id[mid]
            if 'attachments' not in msg:
                msg['attachments'] = []
            msg['attachments'].append(attachment)

        for reaction in reactions:
            aid = reaction.pop('aid')
            reaction['author'] = self.recipients[aid]

            mid = reaction.pop('mid')
            msg = messages_by_id[mid]
            if 'reactions' not in msg:
                msg['reactions'] = []
            msg['reactions'].append(reaction)

    def __iter__(self):
        for recipient_id in self.threads:
            yield self.recipients[recipient_id], self.threads[recipient_id]
