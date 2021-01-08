@mainpage
# Example of obtaining "A" type DNS records via WiFi

(See the README.md file in the upper level Espressif 'examples' directory for more information about examples.)


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
I (589) wifi station: ESP_WIFI_MODE_STA
I (599) wifi: wifi driver task: 3ffc08b4, prio:23, stack:3584, core=0
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (629) wifi: wifi firmware version: 2d94f02
I (629) wifi: config NVS flash: enabled
I (629) wifi: config nano formating: disabled
I (629) wifi: Init dynamic tx buffer num: 32
I (629) wifi: Init data frame dynamic rx buffer num: 32
I (639) wifi: Init management frame dynamic rx buffer num: 32
I (639) wifi: Init management short buffer num: 32
I (649) wifi: Init static rx buffer size: 1600
I (649) wifi: Init static rx buffer num: 10
I (659) wifi: Init dynamic rx buffer num: 32
I (759) phy: phy_version: 4180, cb3948e, Sep 12 2019, 16:39:13, 0, 0
I (769) wifi: mode : sta (30:ae:a4:d9:bc:c4)
I (769) wifi station: wifi_init_sta finished.
I (889) wifi: new:<6,0>, old:<1,0>, ap:<255,255>, sta:<6,0>, prof:1
I (889) wifi: state: init -> auth (b0)
I (899) wifi: state: auth -> assoc (0)
I (909) wifi: state: assoc -> run (10)
I (939) wifi: connected with #!/bin/test, aid = 1, channel 6, BW20, bssid = ac:9e:17:7e:31:40
I (939) wifi: security type: 3, phy: bgn, rssi: -68
I (949) wifi: pm start, type: 1

I (1029) wifi: AP's beacon interval = 102400 us, DTIM period = 3
I (2089) esp_netif_handlers: sta ip: 192.168.77.89, mask: 255.255.255.0, gw: 192.168.77.1
I (2089) wifi station: got ip:192.168.77.89
I (2089) wifi station: connected to ap SSID:myssid password:mypassword
```

Console output if the station failed to connect to AP:
```
I (589) wifi station: ESP_WIFI_MODE_STA
I (599) wifi: wifi driver task: 3ffc08b4, prio:23, stack:3584, core=0
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (599) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (629) wifi: wifi firmware version: 2d94f02
I (629) wifi: config nano formating: disabled
I (629) wifi: Init dynamic tx buffer num: 32
I (629) wifi: Init data frame dynamic rx buffer num: 32
I (639) wifi: Init management frame dynamic rx buffer num: 32
I (639) wifi: Init management short buffer num: 32
I (649) wifi: Init static rx buffer size: 1600
I (649) wifi: Init static rx buffer num: 10
I (659) wifi: Init dynamic rx buffer num: 32
I (759) phy: phy_version: 4180, cb3948e, Sep 12 2019, 16:39:13, 0, 0
I (759) wifi: mode : sta (30:ae:a4:d9:bc:c4)
I (769) wifi station: wifi_init_sta finished.
I (889) wifi: new:<6,0>, old:<1,0>, ap:<255,255>, sta:<6,0>, prof:1
I (889) wifi: state: init -> auth (b0)
I (1889) wifi: state: auth -> init (200)
I (1889) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (1889) wifi station: retry to connect to the AP
I (1899) wifi station: connect to the AP fail
I (3949) wifi station: retry to connect to the AP
I (3949) wifi station: connect to the AP fail
I (4069) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (4069) wifi: state: init -> auth (b0)
I (5069) wifi: state: auth -> init (200)
I (5069) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (5069) wifi station: retry to connect to the AP
I (5069) wifi station: connect to the AP fail
I (7129) wifi station: retry to connect to the AP
I (7129) wifi station: connect to the AP fail
I (7249) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (7249) wifi: state: init -> auth (b0)
I (8249) wifi: state: auth -> init (200)
I (8249) wifi: new:<6,0>, old:<6,0>, ap:<255,255>, sta:<6,0>, prof:1
I (8249) wifi station: retry to connect to the AP
I (8249) wifi station: connect to the AP fail
I (10299) wifi station: connect to the AP fail
I (10299) wifi station: Failed to connect to SSID:myssid, password:mypassword
```

If Wifi Connects it will get information on the IP address of the DNS server set
when DHCP address was established, Class A records on the target hostname

I (2091) wifi station: .Information on Netif connection
I (2101) wifi station: ...Netif is running
I (2101) wifi station: ...Current IP from netif      : 192.168.1.20
I (2111) wifi station: ...Current netmask from netif : 255.255.255.0
I (2121) wifi station: ...Current gateway from netif : 192.168.1.1
I (2121) wifi station: ...Current Hostname from netif: espressif
I (2131) wifi station: ...Name Server Primary (netif): 192.168.1.1
I (2141) wifi station: ...Name Server Sec (netif)    : 0.0.0.0
I (2141) wifi station: ...Name Serv Fallback (netif) : 0.0.0.0
I (2151) wifi station: ...Name Server DNS Max        : 0.0.0.0
I (2161) wifi station:

I (2161) wifi station: .Initialize the Resolver
I (2171) resolv init : ...dnsserver is                : 192.168.1.1
I (2171) resolv init : ...udp connected to            : 192.168.1.1
I (2181) wifi station: ...Returned from resolver init
I (2191) wifi station: ...DNS server from resolv_getserver is: 192.168.1.1
I (2191) wifi station: ...IP address from resolv_lookup not found
I (2201) wifi station:

I (2201) wifi station: .Begin Resolv Query
I (2211) resolv_query: ...entered resolv query. The name is xmpp.dismail.de
I (2221) resolv_query: ...build entry for             : xmpp.dismail.de
I (2221) resolv_query: ...Created record at seq no    : 0
I (2231) resolv_query: ...Record name is              : xmpp.dismail.de
I (2241) resolv_query: ...Record state is             : 1
I (2241) resolv_query: ...Record IP address           : 0.0.0.0
I (2251) wifi station:

I (2251) wifi station: .Begin Check Entries
I (2261) chck_entries: ...begin check entries
I (2261) chck_entries: ...query sent to DNS server
I (2271) wifi station: .Begin Wait
I (2441) resolv_recv : ...resolv_recv function called
I (2441) resolv_recv : ...ID 0
I (2441) resolv_recv : ...Query 128
I (2441) resolv_recv : ...Error 0
I (2451) resolv_recv : ...Num questions 1, answers 1, authrr 0, extrarr 0
I (2461) resolv_recv : ...Answer IP using memcpy             : 116.203.3.253

I (2461) sti_cb     : ...DNS information for xmpp.dismail.de IP is: 116.203.3.253
I (3271) wifi station:

I (3271) wifi station: .END Wait
I (3271) wifi station: ...Check for ip address from table
I (3271) wifi station: ...IP address from resolv_lookup is: 116.203.3.253
I (3281) wifi station:

I (3281) wifi station: .Begin gethostbyname
I (3291) wifi station: ...Gathering DNS records for xmpp.dismail.de
I (3291) wifi station: ...Address No. 0 from DNS: 116.203.3.253
I (3301) wifi station: ...Address No. 1 from DNS was null
I (3301) wifi station: Done with connection... Now shutdown handlers
