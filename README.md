@mainpage
# Example of obtaining "A" type DNS records via WiFi

(See the README.md file in the upper level Espressif 'examples' directory for more information about examples.)

This program demonstrates how to get information on the netif interface, the DNS assigned when
the IP address was assigned, and shows how to get an "A record" using the methodology shown
by Adam Dunkels

It is part of a series of programs

resolv_1_A        -- This was a first try to convert adam dunkels code to ESP32 uses jps
                      functions for htons and parses without using a data structure. It demonstrates
                      function callbacks when a UDP buffer is received and function callbacks
                      when an IP4 address is found. Code only works on A records. When doin This
                      routine, I became aware how much more efficient the struct method for parsing
                      received buffers was. I also used this to learn about what functions LWIP
                      provides. Tis file will only be used for historical purposes

resolv_2_A        -- This project builds on resolv_01. It removes the extra code I had written
                      and fully demonstrates getting A records using the Adam Dunkels method. You
                      would use this code if you wanted to implement a DNS resolver as envisioned by
                      Dunkels for A records only.

resolv_3_A+SRV     -- This projects adds the critical ability to get SRV records and introduces a
                      function res_query_jps, which creates a query buffer, sends it to the DNS
                      server, waits for a reply, copies the buffer into a user supplied buffer, and
                      returns the length of the buffer. This project retains the working Adam
                      Dunkels style code (A records only). This project proves all the features
                      needed to replace the res_query function provided on unix and windows but
                      not available on the ESP32

sti_dns             -- This function demonstrates res_query with sti code. The functions can now be
                      included in other projects when res_query is required.
## How to use example

### Configure the project

```
idf.py menuconfig
```

* Set WiFi SSID and WiFi Password and Maximum retry under Example Configuration Options.

### Build and Flash

Build the project and flash it to the board, then run monitor tool to view serial output:

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for full steps to configure and use ESP-IDF to build projects.

## Example Output
Note that the output, in particular the order of the output, may vary depending on the environment.

Console output if station connects to AP successfully:
```
I (2093) wifi station: .Information on Netif connection
I (2103) wifi station: ...Netif is running
I (2103) wifi station: ...Current IP from netif      : 192.168.1.20
I (2113) wifi station: ...Current netmask from netif : 255.255.255.0
I (2123) wifi station: ...Current gateway from netif : 192.168.1.1
I (2123) wifi station: ...Current Hostname from netif: espressif
I (2133) wifi station: ...Name Server Primary (netif): 192.168.1.1
I (2143) wifi station: ...Name Server Sec (netif)    : 0.0.0.0
I (2143) wifi station: ...Name Serv Fallback (netif) : 0.0.0.0
I (2153) wifi station: ...Name Server DNS Max        : 0.0.0.0
I (2163) wifi station:

I (2163) wifi station: .Initialize the Resolver
I (2173) resolv init : ...dnsserver is                : 8.8.8.8
I (2173) resolv init : ...udp connected to            : 8.8.8.8
I (2183) wifi station: ...Returned from resolver init
I (2183) wifi station: ...DNS server from resolv_getserver is: 8.8.8.8
I (2193) wifi station: ...IP address from resolv_lookup not found
I (2203) res_query_jps:
I (2203) res_query_jps: .Begin res_query_jps function
I (2213) res_query_jps: ...query sent to DNS server
I (2533) resolv_recv : ...resolv_recv function called
I (2533) resolv_recv : ....Buffer length from tot_len is 49
I (2533) resolv_recv : ...ID 99
I (2543) resolv_recv : ...Query 128
I (2543) resolv_recv : ...Error 0
I (2553) resolv_recv : ...Num questions 1, answers 1, authrr 0, extrarr 0
I (2613) res_query_jps: ...payload length from parse = 49
I (2613) wifi station: ...length of returned buffer is 49
I (2613) print_buf   : ....1 Hex in received buffer   : 0
I (2613) print_buf   : ....2 Letter in received buffer: c
I (2623) print_buf   : ....3 Hex in received buffer   : 81
I (2623) print_buf   : ....4 Hex in received buffer   : 80
I (2633) print_buf   : ....5 Hex in received buffer   : 0
I (2643) print_buf   : ....6 Hex in received buffer   : 1
I (2643) print_buf   : ....7 Hex in received buffer   : 0
I (2653) print_buf   : ....8 Hex in received buffer   : 1
I (2663) print_buf   : ....9 Hex in received buffer   : 0
I (2663) print_buf   : ....10 Hex in received buffer   : 0
I (2673) print_buf   : ....11 Hex in received buffer   : 0
I (2673) print_buf   : ....12 Hex in received buffer   : 0
I (2683) print_buf   : ....13 Hex in received buffer   : 4
I (2693) print_buf   : ....14 Letter in received buffer: x
I (2693) print_buf   : ....15 Letter in received buffer: m
I (2703) print_buf   : ....16 Letter in received buffer: p
I (2703) print_buf   : ....17 Letter in received buffer: p
I (2713) print_buf   : ....18 Hex in received buffer   : 7
I (2723) print_buf   : ....19 Letter in received buffer: d
I (2723) print_buf   : ....20 Letter in received buffer: i
I (2733) print_buf   : ....21 Letter in received buffer: s
I (2743) print_buf   : ....22 Letter in received buffer: m
I (2743) print_buf   : ....23 Letter in received buffer: a
I (2753) print_buf   : ....24 Letter in received buffer: i
I (2753) print_buf   : ....25 Letter in received buffer: l
I (2763) print_buf   : ....26 Hex in received buffer   : 2
I (2773) print_buf   : ....27 Letter in received buffer: d
I (2773) print_buf   : ....28 Letter in received buffer: e
I (2783) print_buf   : ....29 Hex in received buffer   : 0
I (2783) print_buf   : ....30 Hex in received buffer   : 0
I (2793) print_buf   : ....31 Hex in received buffer   : 1
I (2803) print_buf   : ....32 Hex in received buffer   : 0
I (2803) print_buf   : ....33 Hex in received buffer   : 1
I (2813) print_buf   : ....34 Hex in received buffer   : C0
I (2823) print_buf   : ....35 Hex in received buffer   : C
I (2823) print_buf   : ....36 Hex in received buffer   : 0
I (2833) print_buf   : ....37 Hex in received buffer   : 1
I (2833) print_buf   : ....38 Hex in received buffer   : 0
I (2843) print_buf   : ....39 Hex in received buffer   : 1
I (2853) print_buf   : ....40 Hex in received buffer   : 0
I (2853) print_buf   : ....41 Hex in received buffer   : 0
I (2863) print_buf   : ....42 Hex in received buffer   : 7
I (2863) print_buf   : ....43 Hex in received buffer   : 7
I (2873) print_buf   : ....44 Hex in received buffer   : 0
I (2883) print_buf   : ....45 Hex in received buffer   : 4
I (2883) print_buf   : ....46 Letter in received buffer: t
I (2893) print_buf   : ....47 Hex in received buffer   : CB
I (2903) print_buf   : ....48 Hex in received buffer   : 3
I (2903) print_buf   : ....49 Hex in received buffer   : FD
I (2913) wifi station: ...End res_query_jps for type A records
I (3913) wifi station:
I (3913) wifi station: ...Start of res_query_jps for SRV records
I (3913) res_query_jps:
I (3913) res_query_jps: .Begin res_query_jps function
I (3923) res_query_jps: ...query sent to DNS server
I (4173) resolv_recv : ...resolv_recv function called
I (4173) resolv_recv : ....Buffer length from tot_len is 81
I (4173) resolv_recv : ...ID 99
I (4183) resolv_recv : ...Query 128
I (4183) resolv_recv : ...Error 0
I (4183) resolv_recv : ...Num questions 1, answers 1, authrr 0, extrarr 0
I (4323) res_query_jps: ...payload length from parse = 81
I (4323) wifi station: ...length of res_query_jps returned buffer 81
I (4323) print_buf   : ....1 Hex in received buffer   : 0
I (4323) print_buf   : ....2 Letter in received buffer: c
I (4333) print_buf   : ....3 Hex in received buffer   : 81
I (4343) print_buf   : ....4 Hex in received buffer   : 80
I (4343) print_buf   : ....5 Hex in received buffer   : 0
I (4353) print_buf   : ....6 Hex in received buffer   : 1
I (4353) print_buf   : ....7 Hex in received buffer   : 0
I (4363) print_buf   : ....8 Hex in received buffer   : 1
I (4373) print_buf   : ....9 Hex in received buffer   : 0
I (4373) print_buf   : ....10 Hex in received buffer   : 0
I (4383) print_buf   : ....11 Hex in received buffer   : 0
I (4383) print_buf   : ....12 Hex in received buffer   : 0
I (4393) print_buf   : ....13 Hex in received buffer   : C
I (4403) print_buf   : ....14 Hex in received buffer   : 5F
I (4403) print_buf   : ....15 Letter in received buffer: x
I (4413) print_buf   : ....16 Letter in received buffer: m
I (4423) print_buf   : ....17 Letter in received buffer: p
I (4423) print_buf   : ....18 Letter in received buffer: p
I (4433) print_buf   : ....19 Hex in received buffer   : 2D
I (4433) print_buf   : ....20 Letter in received buffer: c
I (4443) print_buf   : ....21 Letter in received buffer: l
I (4453) print_buf   : ....22 Letter in received buffer: i
I (4453) print_buf   : ....23 Letter in received buffer: e
I (4463) print_buf   : ....24 Letter in received buffer: n
I (4463) print_buf   : ....25 Letter in received buffer: t
I (4473) print_buf   : ....26 Hex in received buffer   : 4
I (4483) print_buf   : ....27 Hex in received buffer   : 5F
I (4483) print_buf   : ....28 Letter in received buffer: t
I (4493) print_buf   : ....29 Letter in received buffer: c
I (4503) print_buf   : ....30 Letter in received buffer: p
I (4503) print_buf   : ....31 Hex in received buffer   : 7
I (4513) print_buf   : ....32 Letter in received buffer: d
I (4513) print_buf   : ....33 Letter in received buffer: i
I (4523) print_buf   : ....34 Letter in received buffer: s
I (4533) print_buf   : ....35 Letter in received buffer: m
I (4533) print_buf   : ....36 Letter in received buffer: a
I (4543) print_buf   : ....37 Letter in received buffer: i
I (4553) print_buf   : ....38 Letter in received buffer: l
I (4553) print_buf   : ....39 Hex in received buffer   : 2
I (4563) print_buf   : ....40 Letter in received buffer: d
I (4563) print_buf   : ....41 Letter in received buffer: e
I (4573) print_buf   : ....42 Hex in received buffer   : 0
I (4583) print_buf   : ....43 Hex in received buffer   : 0
I (4583) print_buf   : ....44 Hex in received buffer   : 21
I (4593) print_buf   : ....45 Hex in received buffer   : 0
I (4593) print_buf   : ....46 Hex in received buffer   : 1
I (4603) print_buf   : ....47 Hex in received buffer   : C0
I (4613) print_buf   : ....48 Hex in received buffer   : C
I (4613) print_buf   : ....49 Hex in received buffer   : 0
I (4623) print_buf   : ....50 Hex in received buffer   : 21
I (4633) print_buf   : ....51 Hex in received buffer   : 0
I (4633) print_buf   : ....52 Hex in received buffer   : 1
I (4643) print_buf   : ....53 Hex in received buffer   : 0
I (4643) print_buf   : ....54 Hex in received buffer   : 0
I (4653) print_buf   : ....55 Hex in received buffer   : 7
I (4663) print_buf   : ....56 Hex in received buffer   : 7
I (4663) print_buf   : ....57 Hex in received buffer   : 0
I (4673) print_buf   : ....58 Hex in received buffer   : 17
I (4673) print_buf   : ....59 Hex in received buffer   : 0
I (4683) print_buf   : ....60 Hex in received buffer   : A
I (4693) print_buf   : ....61 Hex in received buffer   : 0
I (4693) print_buf   : ....62 Hex in received buffer   : 0
I (4703) print_buf   : ....63 Hex in received buffer   : 14
I (4713) print_buf   : ....64 Letter in received buffer: f
I (4713) print_buf   : ....65 Hex in received buffer   : 4
I (4723) print_buf   : ....66 Letter in received buffer: x
I (4723) print_buf   : ....67 Letter in received buffer: m
I (4733) print_buf   : ....68 Letter in received buffer: p
I (4743) print_buf   : ....69 Letter in received buffer: p
I (4743) print_buf   : ....70 Hex in received buffer   : 7
I (4753) print_buf   : ....71 Letter in received buffer: d
I (4763) print_buf   : ....72 Letter in received buffer: i
I (4763) print_buf   : ....73 Letter in received buffer: s
I (4773) print_buf   : ....74 Letter in received buffer: m
I (4773) print_buf   : ....75 Letter in received buffer: a
I (4783) print_buf   : ....76 Letter in received buffer: i
I (4793) print_buf   : ....77 Letter in received buffer: l
I (4793) print_buf   : ....78 Hex in received buffer   : 2
I (4803) print_buf   : ....79 Letter in received buffer: d
I (4803) print_buf   : ....80 Letter in received buffer: e
I (4813) print_buf   : ....81 Hex in received buffer   : 0
I (4823) wifi station: ...End res_query_jps for SRV records
I (4823) wifi station:

I (4833) wifi station: .Begin Resolv Query
I (4833) resolv_query: ...entered resolv query. The name is xmpp.dismail.de
I (4843) resolv_query: ...build entry for             : xmpp.dismail.de
I (4853) resolv_query: ...Created record at seq no    : 0
I (4853) resolv_query: ...Record name is              : xmpp.dismail.de
I (4863) resolv_query: ...Record state is             : 1
I (4873) resolv_query: ...Record IP address           : 0.0.0.0
I (4873) wifi station:

I (4883) wifi station: .Begin Check Entries
I (4883) chck_entries: ...begin check entries
I (4893) chck_entries: ...query sent to DNS server
I (4893) wifi station: .Begin Wait
I (4923) resolv_recv : ...resolv_recv function called
I (4923) resolv_recv : ....Buffer length from tot_len is 49
I (4923) resolv_recv : ...ID 0
I (4923) resolv_recv : ...Query 128
I (4923) resolv_recv : ...Error 0
I (4933) resolv_recv : ...Num questions 1, answers 1, authrr 0, extrarr 0
I (4943) resolv_recv : ...Answer IP using memcpy             : 116.203.3.253

I (4943) sti_cb     : ...DNS information for xmpp.dismail.de IP is: 116.203.3.253
I (5893) wifi station:

I (5893) wifi station: .END Wait
I (5893) wifi station: ...Check for ip address from table
I (5893) wifi station: ...IP address from resolv_lookup is: 116.203.3.253
I (5903) wifi station:

I (5903) wifi station: .Begin gethostbyname
I (6123) wifi station: ...Gathering DNS records for xmpp.dismail.de
I (6123) wifi station: ...Address No. 0 from DNS: 116.203.3.253
I (6123) wifi station: ...Address No. 1 from DNS was null
I (6133) wifi station: Done with connection... Now shutdown handlers
