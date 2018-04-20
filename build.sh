# generate the code to create and parse the messages
protoc -I=src/ --java_out=src/ src/protos/mpt.proto src/protos/bverifyprotocolapi.proto 
