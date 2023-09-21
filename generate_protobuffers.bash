wget https://raw.githubusercontent.com/signalapp/Signal-Android/main/app/src/main/protowire/Backups.proto
protoc --python_out=. Backups.proto
protoc --python_out=. Reactions.proto
