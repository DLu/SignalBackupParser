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
        if hasattr(frame.header, 'version'):
            self.backup_version = frame.header.version
        else:
            self.backup_version = 0

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

    def read_frame(self, length, with_framelength_in_mac=-1, with_iv=False):
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

        if with_framelength_in_mac != -1:
            mac.update(with_framelength_in_mac)

        ofile = io.BytesIO()

        def get_chunk(max_length):
            return self.read(max_length)

        enc_iv_idx = 0 if with_framelength_in_mac == -1 else len(with_framelength_in_mac)
        bytesleft = length

        while (bytesleft != 0):
            enc_chunk = get_chunk(min(bytesleft, 16 - enc_iv_idx));
            bytesleft -= len(enc_chunk)

            mac.update(enc_chunk)
            output = strxor.strxor(
                enc_chunk,
                self.aes_cipher.encrypt(enc_iv)[enc_iv_idx:enc_iv_idx + len(enc_chunk)]
            )

            ctr = int.from_bytes(enc_iv, byteorder='big') + 1
            enc_iv = int.to_bytes(ctr, length=16, byteorder='big')
            enc_iv_idx = 0
            ofile.write(output)

        our_mac = mac.digest()
        our_mac = our_mac[:10]  # trim to 1st 10 bytes
        their_asset_mac = self.read(10)

        assert hmac.compare_digest(our_mac, their_asset_mac)
        return ofile.getvalue()

    def get_framelength(self, encryptedlength):
        val = int.to_bytes(self.counter, length=16, byteorder='little')
        self.iv[3] = val[0]
        self.iv[2] = val[1]
        self.iv[1] = val[2]
        self.iv[0] = val[3]
        enc_iv = self.iv
        output = strxor.strxor(
            encryptedlength,
            self.aes_cipher.encrypt(enc_iv)[:len(encryptedlength)]
        )
        return output

    def __iter__(self):
        last_bytes = 0
        with click.progressbar(length=self.bytes_total) as bar:
            while self.bytes_read < self.bytes_total:
                # Read Frame
                frame_length_b = self.read(4)
                if self.backup_version == 0:
                    frame_length = int.from_bytes(frame_length_b, byteorder='big')
                else:
                    frame_length = int.from_bytes(self.get_framelength(frame_length_b), byteorder='big')

                frame = BackupFrame()
                frame.ParseFromString(self.read_frame(frame_length - 10, (-1 if self.backup_version == 0 else frame_length_b), False))

                # Read Attachment
                attachment = None
                attachment_length = frame.attachment.length or frame.avatar.length or frame.sticker.length
                if attachment_length:
                    attachment = self.read_frame(attachment_length, with_iv=True)
                yield frame, attachment
                bar.update(self.bytes_read - last_bytes)
                last_bytes = self.bytes_read


def split_into_fields(s):
    if '(' not in s:
        return s.split(',')
    tokens = []
    i = 0
    while i < len(s):
        if ',' not in s[i:]:
            tokens.append(s[i:])
            break
        a = s.index(',', i)
        if '(' in s[i:]:
            b = s.index('(', i)
        else:
            b = len(s)
        if a < b:
            tokens.append(s[i: a])
            i = a + 1
        else:
            c = s.index(')', b)
            if ',' in s[c:]:
                a = s.index(',', c)
            else:
                a = len(s)
            tokens.append(s[i: a])
            i = a + 1
    return tokens


class DictReader:
    def __init__(self, filename, password):
        self.frame_reader = FrameReader(filename, password)
        self.datatypes = {}

    def _get_table_definition(self, statement):
        create_pattern = re.compile(r'^CREATE TABLE "?(\w+)"?\s*\((.*)\)$', re.DOTALL)
        m = create_pattern.match(statement)
        if not m:
            click.secho(f'Bad table definition {statement}', fg='yellow')
            return None, None
        fields = []
        for field in split_into_fields(m.group(2)):
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
                try:
                    s = eval('b' + value).decode()
                except SyntaxError:
                    s = value
                parameters.append(s)
            else:
                parameters.append(eval(value))

        return table, parameters

    def __iter__(self):
        version = None
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

                    if version == 167 and table == 'sms':
                        del parameters[6]

                    for (name, dt), value in zip(self.datatypes[table], parameters):
                        if value is None:
                            continue
                        entry[name] = value
                    yield table, entry
                else:
                    click.secho(f'Unmatched statement {statement}', fg='yellow')
                    exit(1)
            elif frame.version.version:
                version = frame.version.version
                yield 'version', frame.version.version
            elif frame.attachment:
                entry = {'attachmentId': frame.attachment.attachmentId, 'rowId': frame.attachment.rowId,
                         'data': att}
                yield 'attachment', entry
            else:
                click.secho(f'Unmatched frame type {frame}', fg='red')
                exit(1)


# Base Types as defined here:
# https://github.com/signalapp/Signal-Android/blob/6ccfab4087ba7a6f4d5ca9062ed56d3849d19efa/
#     app/src/main/java/org/thoughtcrime/securesms/database/MessageTypes.java#L36
MESSAGE_TYPES = [
    # 0-5
    '', 'incoming audio call', 'outgoing audio call', 'missed audio call', 'joined', 'unsupported message',
    # 6-10
    'invalid message', 'profile change', 'missed video call', 'gv1 migration', 'incoming video call',
    # 11-15
    'outgoing video call', 'group call', 'bad decrypt', 'change number', 'boost request',
    # 16-20
    'thread merge', 'sms export', 'session_switchover', '', 'inbox',
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
        group_membership = collections.defaultdict(set)
        reactions = []
        orphan_threads = collections.defaultdict(list)

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
                for key in ['thread_recipient_id', 'recipient_ids', 'recipient_id']:
                    if key in entry:
                        thread_mapping[entry['_id']] = entry[key]

            elif table in ['sms', 'mms', 'message']:
                msg = {}
                for date_key in ['date', 'date_sent']:
                    if date_key in entry:
                        msg['date'] = entry[date_key]
                        break
                else:
                    raise RuntimeError('Cannot find date key. Available: ' + '/'.join(entry.keys()))

                if 'type' in entry:
                    base_type = entry['type'] & MESSAGE_TYPE_MASK
                    msg['type'] = MESSAGE_TYPES[base_type]

                if 'address' in entry:
                    if entry.get('server_guid') is None:
                        msg['address'] = 1
                    else:
                        msg['address'] = entry['address']
                elif 'from_recipient_id' in entry:
                    msg['address'] = entry['from_recipient_id']
                elif msg['type'] in ['sent', 'outgoing video call']:
                    msg['address'] = 1

                if 'body' in entry:
                    msg['body'] = entry['body']

                messages_by_id[entry['_id']] = msg

                thread_id = entry['thread_id']
                if thread_id in thread_mapping:
                    recipient_id = thread_mapping[thread_id]
                    self.threads[recipient_id].append(msg)
                else:
                    orphan_threads[thread_id].append(msg)

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
            elif table == 'group_membership':
                group_membership[entry['group_id']].add(entry['recipient_id'])

        for thread_id, msgs in orphan_threads.items():
            if thread_id in thread_mapping:
                recipient_id = thread_mapping[thread_id]
                for msg in msgs:
                    self.threads[recipient_id].append(msg)
            else:
                click.secho(f'Cannot find thread for thread_id {thread_id}. {len(msgs)} orphan messages.', fg='red')

        for entry in groups:
            group = {'name': entry['title'], 'members': [], 'group_id': entry['group_id']}
            if 'members' in entry:
                for member in entry['members'].split(','):
                    mid = int(member)
                    group['members'].append(dict(self.recipients[mid]))
            else:
                for mid in group_membership[entry['group_id']]:
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
