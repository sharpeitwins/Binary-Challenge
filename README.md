                     CTF Challenge
                  ----------------------

    So two things that I did, when I created this challenge
    was to change the entry point and also corrupt the UPX packer. 


    bane@dev$ gcc ctf_binary.c -Wl,-emain_ -o apt666

    bane@dev$ upx apt666


    Using the usual ways of scoping out a file at first, coming to
    find the file is packed by UPX should be simple. Trying to 
    unpack it will dump out an error. Checking the hexdump, the user
    should see the UPX! has been patched to NOP!.

    Using okteta, I just edited the first occurance of 55 50 58 21 | UPX! 
    in the binary.

    Patched bytes

    000000e0  10 00 00 00 00 00 00 00  b5 16 ac cf 4e 4f 50 21  |............NOP!|

    Correct bytes

    000000e0  10 00 00 00 00 00 00 00  b5 16 ac cf 55 50 58 21  |............UPX!|


    bane@dev$ upx -d apt666

    Okay, now we have the unpacked binary. 

    Using readelf, we can find our entry point.

    bane@dev$ readelf -h apt666
     ***
       Entry point address:               0x19ef


    I cut the extra details out, we just need our entry point.

    bane@dev$ objdump -t apt666 | grep 13a9
    00000000000019ef g     F .text	0000000000000057              main_


    Our symbol table shows main_, which isn't what would be a regular entry main()
    call. 

    bane@dev$ objdump -t a.out | grep main
    00000000000019ef g     F .text	0000000000000057              main_
    00000000000019df g     F .text	0000000000000010              main


    Our real main is at address 0x19df, which should be our correct entry point.

    Before we patch the binary, the main_ function
    created a file named file.txt that read

    Your computer has been infected, please send BTC to 
                          address: dGh1Z3s3cnlfaDRyZDNyX24zckR9



    The b64 decodes to: thug{7ry_h4rd3r_n3rD}

    Which was a fake flag for the people that just hit strings on the binary.
    False positive.

    Using radare2, we can look further to our unpacked binary. We will step into
    our main function first. 



    bane@dev$ r2 -w apt666 -s 0x19df -c 'pd 10'
        ;-- main:
                0x000019df      f3             invalid
                0x000019e0      0f             invalid
                0x000019e1      1e             invalid
                0x000019e2      fa             cli
                0x000019e3      55             push rbp
                0x000019e4      4889e5         mov rbp, rsp
                0x000019e7      e8dbfbffff     call sym.send_icmp
                0x000019ec      90             nop
                0x000019ed      5d             pop rbp
                0x000019ee      c3             ret


    Let's resolve some addresses, to get a better idea of where the address
    for send_icmp is.

    [0x000019df]> f sym.send_icmp 

    We see it is calling another function called send_icmp. Now let's find the
    address.

    Now, when we do


    [0x000019df]> pd 10
                ;-- main:
                ;-- rip:
                ;-- send_icmp:
                0x000019df      f3             invalid
                0x000019e0      0f             invalid
                0x000019e1      1e             invalid
                0x000019e2      fa             cli
                0x000019e3      55             push rbp
                0x000019e4      4889e5         mov rbp, rsp
                0x000019e7      e8dbfbffff     call 0x15c7
                0x000019ec      90             nop
                0x000019ed      5d             pop rbp
                0x000019ee      c3             ret



    We see the address of send_icmp is at 0x15c7


    [0x000019df]> s 0x15c7
    [0x000015c7]> pd 255
                ***
                0x0000163c      ba28000000     mov edx, 0x28               ; '('
                0x00001641      be00000000     mov esi, 0
                0x00001646      4889c7         mov rdi, rax
                0x00001649      e8d2fbffff     call sym.imp.memset
                0x0000164e      488b4de0       mov rcx, qword [rbp - 0x20]
                0x00001652      488d8520ffff.  lea rax, qword [rbp - 0xe0]
                0x00001659      ba0f000000     mov edx, 0xf
                0x0000165e      4889ce         mov rsi, rcx
                0x00001661      4889c7         mov rdi, rax
                0x00001664      e847fbffff     call sym.imp.strncpy
                0x00001669      488d45a0       lea rax, qword [rbp - 0x60]
                0x0000166d      ba30000000     mov edx, 0x30               ; '0'
                0x00001672      be00000000     mov esi, 0
                0x00001677      4889c7         mov rdi, rax
                0x0000167a      e8a1fbffff     call sym.imp.memset
                0x0000167f      c745a4020000.  mov dword [rbp - 0x5c], 2
                0x00001686      c745a8010000.  mov dword [rbp - 0x58], 1
                0x0000168d      c745a0010000.  mov dword [rbp - 0x60], 1
                0x00001694      c745d4170000.  mov dword [rbp - 0x2c], 0x17
                0x0000169b      488b45f8       mov rax, qword [rbp - 8]
                0x0000169f      c60074         mov byte [rax], 0x74        ; 't'
                                                                           ; [0x74:1]=0
                0x000016a2      488b45f8       mov rax, qword [rbp - 8]
                0x000016a6      4883c001       add rax, 1
                0x000016aa      c60068         mov byte [rax], 0x68        ; 'h'
                                                                           ; [0x68:1]=216
                0x000016ad      488b45f8       mov rax, qword [rbp - 8]
                0x000016b1      4883c002       add rax, 2
                0x000016b5      c60075         mov byte [rax], 0x75        ; 'u'
                                                                           ; [0x75:1]=0
                0x000016b8      488b45f8       mov rax, qword [rbp - 8]
                0x000016bc      4883c003       add rax, 3
                0x000016c0      c60067         mov byte [rax], 0x67        ; 'g'
                                                                           ; [0x67:1]=0
                0x000016c3      488b45f8       mov rax, qword [rbp - 8]
                0x000016c7      4883c004       add rax, 4
                0x000016cb      c6007b         mov byte [rax], 0x7b        ; '{'
                                                                           ; [0x7b:1]=0
                0x000016ce      488b45f8       mov rax, qword [rbp - 8]
                0x000016d2      4883c005       add rax, 5
                0x000016d6      c60035         mov byte [rax], 0x35        ; '5'
                                                                           ; [0x35:1]=0
                0x000016d9      488b45f8       mov rax, qword [rbp - 8]
                0x000016dd      4883c006       add rax, 6
                0x000016e1      c6006d         mov byte [rax], 0x6d        ; 'm'
                                                                           ; [0x6d:1]=0
                0x000016e4      488b45f8       mov rax, qword [rbp - 8]
                0x000016e8      4883c007       add rax, 7
                0x000016ec      c60030         mov byte [rax], 0x30        ; '0'
                                                                           ; [0x30:1]=0
                0x000016ef      488b45f8       mov rax, qword [rbp - 8]
                0x000016f3      4883c008       add rax, 8
                0x000016f7      c6006b         mov byte [rax], 0x6b        ; 'k'
                                                                           ; [0x6b:1]=0
                0x000016fa      488b45f8       mov rax, qword [rbp - 8]
                0x000016fe      4883c009       add rax, 9
                0x00001702      c60033         mov byte [rax], 0x33        ; '3'
                                                                           ; [0x33:1]=0
                0x00001705      488b45f8       mov rax, qword [rbp - 8]
                0x00001709      4883c00a       add rax, 0xa
                0x0000170d      c6005f         mov byte [rax], 0x5f        ; '_'
                                                                           ; [0x5f:1]=0
                0x00001710      488b45f8       mov rax, qword [rbp - 8]
                0x00001714      4883c00b       add rax, 0xb
                0x00001718      c60077         mov byte [rax], 0x77        ; 'w'
                                                                           ; [0x77:1]=0
                0x0000171b      488b45f8       mov rax, qword [rbp - 8]
                0x0000171f      4883c00c       add rax, 0xc
                0x00001723      c60033         mov byte [rax], 0x33        ; '3'
                                                                           ; [0x33:1]=0
                0x00001726      488b45f8       mov rax, qword [rbp - 8]
                0x0000172a      4883c00d       add rax, 0xd
                0x0000172e      c60033         mov byte [rax], 0x33        ; '3'
                                                                           ; [0x33:1]=0
                0x00001731      488b45f8       mov rax, qword [rbp - 8]
                0x00001735      4883c00e       add rax, 0xe
                0x00001739      c60064         mov byte [rax], 0x64        ; 'd'
                                                                           ; [0x64:1]=0
                0x0000173c      488b45f8       mov rax, qword [rbp - 8]
                0x00001740      4883c00f       add rax, 0xf
                0x00001744      c6005f         mov byte [rax], 0x5f        ; '_'
                                                                           ; [0x5f:1]=0
                0x00001747      488b45f8       mov rax, qword [rbp - 8]
                0x0000174b      4883c010       add rax, 0x10
                0x0000174f      c60034         mov byte [rax], 0x34        ; '4'
                                                                           ; [0x34:1]=64
                0x00001752      488b45f8       mov rax, qword [rbp - 8]
                0x00001756      4883c011       add rax, 0x11
                0x0000175a      c6005f         mov byte [rax], 0x5f        ; '_'
                                                                           ; [0x5f:1]=0
                0x0000175d      488b45f8       mov rax, qword [rbp - 8]
                0x00001761      4883c012       add rax, 0x12
                0x00001765      c60033         mov byte [rax], 0x33        ; '3'
                                                                           ; [0x33:1]=0
                0x00001768      488b45f8       mov rax, qword [rbp - 8]
                0x0000176c      4883c013       add rax, 0x13
                0x00001770      c60076         mov byte [rax], 0x76        ; 'v'
                                                                           ; [0x76:1]=0
                0x00001773      488b45f8       mov rax, qword [rbp - 8]
                0x00001777      4883c014       add rax, 0x14
                0x0000177b      c60033         mov byte [rax], 0x33        ; '3'
                                                                           ; [0x33:1]=0
                0x0000177e      488b45f8       mov rax, qword [rbp - 8]
                0x00001782      4883c015       add rax, 0x15
                0x00001786      c60072         mov byte [rax], 0x72        ; 'r'
                                                                           ; [0x72:1]=0
                0x00001789      488b45f8       mov rax, qword [rbp - 8]
                0x0000178d      4883c016       add rax, 0x16
                0x00001791      c6007d         mov byte [rax], 0x7d        ; '}'
                                                                           ; [0x7d:1]=0
            ***
                0x000019de      c3             ret


    Stepping into 0x15c7, we see the inside of the function. So, we see
    that r2 has resolved the UTF8 characters being pushed into an array. 
    We can copy those and get the string. 

    thug{5m0k3_w33d_4_3v3r}
