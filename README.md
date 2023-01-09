# tftp_client
[tftp](https://datatracker.ietf.org/doc/html/rfc1350
) client written in Zig language

## How to build

```shell-session
$ zig build
$ ls -l zig-out/bin/tftp_client 
-rwxrwxr-x 1 koba koba 1705368 Jan  9 16:32 zig-out/bin/tftp_client
```

## Usage
```shell-session
$ ./zig-out/bin/tftp_client 
Usage: ./zig-out/bin/tftp_client get|put host remote_filename [local_filename]
```

```shell-session
$ ./zig-out/bin/tftp_client get localhost hello.txt
1673249781311:send_bytes=18, "\0\1hello.txt\0octet\0", a=127.0.0.1:69
1673249781314:recv_bytes=18, [00 03 00 01  ...], os.linux.sockaddr{ .family = 2, .data = { 169, 222, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 } }
1673249781314:send_bytes=4, [00 04 00 01 ]
```

Now verbose mode is hard coded to be true.
