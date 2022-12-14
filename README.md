# SignalBackupParser
A Python library for reading Signal backup files.

## Setup
1. Install the protobuf compiler with `sudo apt install protobuf-compiler`
1. Run `bash generate_protobuffers.bash` to generate `Backups_pb2.py` and `Reactions_pb2.py`
1. `sudo pip3 install -r requirements.txt`

## Usage
There are three primary classes with different layers of abstraction. **`FrameReader`** will yield the `BackupFrame` object [defined in the protobuffers](https://github.com/signalapp/Signal-Android/blob/main/app/src/main/proto/Backups.proto#L72) and the data for the attachment (if any).

    for frame, attachment in FrameReader(input_path, password_without_spaces):
        print(frame)

Alternatively, you can use the **`DictReader`** class to transform the frames into a representation more akin to their natural database structure, iterating over tuples with a string for the name of the table and a dictionary with the fields and values.

    for table, entry in DictReader(input_path, password_without_spaces):
        print(table, len(entry))

Finally, you can also ignore a lot of the data and present a view more akin to how a user would read it, using the **`ThreadReader`** class.

    for thread_info, thread in ThreadReader(input_path, password_without_spaces):
        print(thread_info)
        print(len(thread))

## Acknowledgments
 * Much of the key Python code is derived from [SoftwareArtisan](https://github.com/SoftwareArtisan)'s [signal-backup-exporter](https://github.com/SoftwareArtisan/signal-backup-exporter/blob/master/signal_backup_exporter.py)
 * Additional structuring was derived from [signalbackup-tools](https://github.com/bepaald/signalbackup-tools/blob/757966081627c6c99922a21f953d0f770de4c140/sqlcipherdecryptor/sqlcipherdecryptor.h) and [signal-back](https://github.com/xeals/signal-back/blob/7b9bc2112afa24316da1e2c515e067f69f91d5c4/types/backup.go#L328)
