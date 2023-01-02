# <div align="center">Multi-Channel Machine-in-the-Middle</div>

<a id="intro"></a>
# 1. Introduction

This is a **Python implementation of a Multi-Channel Machine-in-the-Middle (MC-MitM) position**.
Using a MC-MitM position it becomes possible to easily manipulate Wi-Fi traffic, e.g., an adversary
can use it to reliably block, modify, drop, or delay Wi-Fi frames between a client and an Access
Point (AP). It works by cloning the target AP on a different channel, tricking victim clients into
connecting to the AP on this rogue channel, and then forward frames to and from the real AP. In
other words, in a MC-MitM position, frames are forwarded between the real and rogue channel.
The goal of this code is to more rapidly proto-type and practically confirm attacks that require
a multi-channel MitM position.

To trick victims into connecting to the fake AP on the rogue channel, the script will broadcast
beacons on the rogue channel, and the script will also spoof beacons with a Channel Switch
Announcement (CSA) on the channel of the real AP. These spoofed CSA announcements inform clients
that the AP will be switching to the rouge channel.

If you are using this tool, you can cite the original paper that introduced the MC-MitM position:

	@InProceedings{vanhoef-acsac2014-full,
	  author =       {Vanhoef, Mathy and Piessens, Frank},
	  title =        {Advanced {Wi-Fi} attacks using commodity hardware},
	  booktitle =    {Proceedings of the 30\textsuperscript{th} Annual Computer Security Applications Conference (ACSAC '14)},
	  year =         {2014},
	  month =        dec,
	  pages =        {256--265},
	  publisher =    {ACM}
	}

Note that the original [ModWifi MC-MitM code](https://github.com/vanhoefm/modwifi#channel-mitm-and-tkip-broadcast-attack),
which corresponds to the above paper, was written in C and only supports Atheros Wi-Fi dongles.
The Python implementation in this repository is easier to modify, at the cost of being a bit
slower due to the usage of Python.


<a id="id-prerequisites"></a>
# 2. Prerequisites

The test tool was tested on Ubuntu 22.04. To install the required dependencies, execute:

	# Ubuntu:
	sudo apt-get update
	sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential macchanger net-tools virtualenv \
		rfkill hostapd wpa_supplicant

Then clone this repository **and its submodules**, and configure a virtual python3
environment so the correct scapy library will be used:

	git clone https://github.com/vanhoefm/mc-mitm.git --recursive
	cd mc-mitm
	./pysetup.sh

The above instructions only have to be executed once. After pulling in new code it's
recommended to execute `./pysetup.sh` again so that any new Python dependencies will
be loaded.


<a id="launch-attack"></a>
# 3. Launching the attack

The attack **requires two wireless network cards** and you must be within radio distance of both
the client and the AP. The most reliable network card is one based on [`ath9k_htc`](https://wikidevi.wi-cat.ru/Ath9k_htc).
An example is a [Technoethical N150 HGA](https://tehnoetic.com/tet-n150hga). You can also use
`mac80211_hwsim` on Linux to use this script with simulated interfaces.


<a id="launch-attack-mitm"></a>
## 3.1. Starting the Machine-in-the-Middle

Every time you want to use the test tool, you first have to load the virtual python environment
as root. This can be done using:

	sudo su
	source venv/bin/activate

You should now disable Wi-Fi in your network manager so it will not interfere with the test tool.
You can then start the attack tool by executing:

	./mc-mitm.py wlan1 wlan2 testnetwork --target 00:11:11:11:11:11 --continuous-csa

The parameters are as follows:

- `wlan1`: this is the wireless network card that will listen to traffic on the channel of the target (real) AP.

- `wlan2`: this is the wireless network card that will advertise a rogue clone of the target AP
  on a different channel.

- `testnetwork`: this is the SSID of the Wi-Fi network we are targetting.

- `--target`: this parameter can be used to target a single client. This is strongly recommended
  because targeting only one client drastically improves the reliability of the attack.

- `--continuous-csa`: this means beacons with CSA elements will be continuously spoofed in the
  channel containing the real AP. This improves the change that any target client will move to
  the rogue channel.

You can execute the script before or after the targeted client connects to the network. If you
want to intercept or target the connection process you have to start the script first and then
connect with the target client to the network. Otherwise, when targeting frames after the
connection process,, you can first start the client and afterwards start the script. The script
will output **"Established MitM position against client"** in green when the machine-in-the-middle
position has been successfully established.

Optional arguments:

- `--debug`: output extra debugging information.


<a id="launch-attack-simulated"></a>
## 3.2. Example with simulated interfaces

You can try the script and any attacks in a simulated environment as well. This increases
the reliability of establishing a MC-MitM position and makes (initial) experiments much
easier. For instance, you can run the script in a virtual machine without requiring physical
Wi-Fi dongles. This is done by using simulated Linux Wi-Fi interfaces. On Linux, enable these
[simulated Wi-Fi interfaces](https://github.com/vanhoefm/libwifi/blob/master/docs/linux_tutorial.md) 
as follows:

	modprobe mac80211_hwsim radios=4

This will create 4 simulated Wi-Fi interface. Now start the example target (real) AP that 
we will attack:

	sudo hostapd example/hostapd.conf

Let's now start the machine-in-the-middle script that will wait for a victim to connect:

	sudo su
	source venv/bin/activate
	./mc-mitm.py wlan2 wlan3 testnetwork --target 02:00:00:00:01:00 --continuous-csa

Notice that in this example we will target a specific client MAC address. Targeting
a specific test client improves the reliability of the attack (frames will be acknowleged
and not needlessly retransmitted). Now start the victim client:

	sudo wpa_supplicant -D nl80211 -i wlan1 -c example/supplicant.conf

The script should now established a MitM between the client and AP. See [example output](#example)
for the expected output of the script.


<a id="development"></a>
# 4. Development notes

- You can extend the functions `should_forward` and `modify_packet` to perform attacks once a MC-MitM has
  been established. These functions control whether packets are forwarded and/or modified, respectively.

- If you want to modify the beacon that is broadcasted, you must modify `self.beacon` that is given as
  an argument to `start_ap`. You can also modify the broadcasted beacon _during_ an attack: that requires
  first calling `stop_ap` and then `start_ap` using the new beacon.

- Read the [design discussion](mc-mitm.py#L8) to understand _why_ the interfaces are configured
  in the way they are. The main difficulty is assuring that frame acknowledgement and retransmission
  works reliably, and to have an easy way to constantly broadcast beacons.

- An older version of MC-MitM used Hostapd to broadcast beacons and to reply to probe requests. You can
  still access this version on the `hostap-version` branch. This may be useful if you want to reuse
  functionality of Hostapd.


<a id="notes"></a>
# 5. Experimental notes

## 5.1. General Notes

When performing the attack in practice, with real Wi-Fi dongles, I have found it useful to:

- Put the target network on channel 1 or 11. The rogue AP will be put on a "far away" channel, reducing
  possible cross-channel interference in the multi-channel MitM.

- Configure the target network to use an older network mode such as 802.11b. This makes it easier
  ot capture all frames sent by the AP and client, making the attack more reliable.

## 5.2. Attacking Linux

- Hostapd on Linux requires that the association response it sends is acknowledged. Otherwise it
  will disconnect the client. This is not an issue, since the script configures the interface so
  that this frame will be acknowledged. See the [design discussion](mc-mitm.py#L8) in the Python
  code.

- As a client, the Linux kernel requires that the authentication and association response is received
  fairly quickly after sending the authentication or association request, respectively. Otherwise the
  connection attempt fails. This means a victim Linux client will fail to connect if the MC-MitM
  script it too slow with forwarding frames, and if this happens you can see the following kernel
  log messages when executing `dmesg`:

		[549625.712318] wlan1: send auth to 02:00:00:00:00:00 (try 1/3)
		[549625.821512] wlan1: send auth to 02:00:00:00:00:00 (try 2/3)
		[549625.931563] wlan1: send auth to 02:00:00:00:00:00 (try 3/3)
		[549626.041561] wlan1: authentication with 02:00:00:00:00:00 timed out

		[549680.921287] wlan1: associate with 02:00:00:00:00:00 (try 1/3)
		[549681.041303] wlan1: associate with 02:00:00:00:00:00 (try 2/3)
		[549681.151310] wlan1: associate with 02:00:00:00:00:00 (try 3/3)
		[549681.261511] wlan1: association with 02:00:00:00:00:00 timed out

  If these timeouts happen, make sure that `Dot11Auth` and `Dot11AssoReq` are instantly forwarded
  by the script. Alternatively, if your attack doesn't target the connection process, you can start
  the script after the Linux client has connected (e.g., in case you target data frames).

  Another alternative is to use the [ModWifi C implementation](https://github.com/vanhoefm/modwifi#channel-mitm-and-tkip-broadcast-attack),
  but that's harder to modify and requires specific Atheros dongles.

  Against Android, the MC-MitM could be reliably established while the client is connecting and while
  the client was already connected, even when the authentication or association request was forwarded
  quite slow. In other words, the tested Android device (Pixel 4 XL) was not affected by the above
  timing constraints of Linux.

- When targeting a Linux client, the kernel will save both the real and rogue AP when scanning
  for networks. Both these APs/BSS will be in a scan result, even if the MAC addresses of the AP
  are the same. This can be seen in the debug output of `wpa_supplicant`:

		wlan1: Event SCAN_RESULTS (3) received
		wlan1: Scan completed in 8.591472 seconds
		nl80211: Received scan results (2 BSSes)
		wlan1: BSS: Start scan result update 1
		wlan1: BSS: Add new id 0 BSSID 02:00:00:00:00:00 SSID 'testnetwork' freq 2462
		BSS: 02:00:00:00:00:00 has multiple entries in the scan results - select the most current one
		Previous last_update: 109926.096453 (freq 2462)
		New last_update: 109925.251453 (freq 2412)
		Ignore this BSS entry since the previous update looks more current
		BSS: last_scan_res_used=1/32
		wlan1: New scan results available (own=1 ext=0)

  When `wpa_supplicant` notices duplicate scan results for the same AP/BSS, it will pick the
  latest one. This means that to assure the victim Linux client will connect to the rogue AP on
  the rogue channel, we need to assure that the scan result of the rogue AP is the latest one.


<a id="usage"></a>
# 6. Usage in research

The current Python code is based on older MC-MitM version, and those older versions were used in
the following research or projects:

- The first implementation of the multi-channel machine-in-the-middle was done in C and only supported
  Atheros Wi-Fi dongles. See the [ModWifi MC-MitM code](https://github.com/vanhoefm/modwifi#channel-mitm-and-tkip-broadcast-attack).

- The [KRACK all-zero key PoC](https://github.com/vanhoefm/krackattacks-poc-zerokey/blob/research/krackattack/krack-all-zero-tk.py)
  is the first implementation of the MC-MitM position in Python.

- Others [reproduced the above KRACK all-zero key PoC and added comments to the code](https://github.com/lucascouto/krackattack-all-zero-tk-key).
  These comments may be useful to further understand the code.

- The above Python MC-MitM was also used as the basis for the proof-of-concept attacks for the
  [FragAttacks](https://fragattacks.com) research. This code is currently not public but can be
  requested if you want to do research with it.


<a id="example-output"></a>
# 7. Example output

## Against simulated Linux interfaces (Jan 1, 2022)

	[mathy@zbook-mathy mc-mitm]$ ./pysetup.sh
	[mathy@zbook-mathy mc-mitm]$ sudo su
	[root@zbook-mathy mc-mitm]# source venv/bin/activate
	(venv) [root@zbook-mathy mc-mitm]# ./mc-mitm.py wlan2 wlan3 testnetwork --target 02:00:00:00:01:00 --continuous-csa
	[01:39:07] Note: disable Wi-Fi in your network manager so it doesn't interfere with this script
	[01:39:07] Note: keep >1 meter between interfaces. Else packet delivery is unreliable & target may disconnect
	[01:39:07] Monitor mode: using wlan2 on real channel and wlan3 on rogue channel.
	[01:39:07] Searching for target network...
	[01:39:07] Target network 02:00:00:00:00:00 detected on channel 1
	[01:39:07] Will use wlan3ap to create rogue AP on channel 11
	[01:39:07] Setting MAC address of wlan3ap to 02:00:00:00:00:00
	[01:39:07] Starting AP using: iw dev wlan3ap ap start testnetwork 2462 100 1 head 80000000ffffffffffff02000000000002000000000000000d01f80f29f1050064001104000b746573746e6574776f726b010882848b960c12182403010b tail 2a010432043048606c30140100000fac040100000fac040100000fac020c003b0251007f080400400000000040dd180050f2020101010003a4000027a4000042435e0062322f00
	[01:39:07] Giving the rogue AP one second to initialize ...
	[01:39:08] Injected 4 CSA beacon pairs (moving stations to channel 11)
	[01:39:19] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: Auth(seq=1830, status=0) -- MitM'ing
		       Established MitM position against client 02:00:00:00:01:00
	[01:39:19] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: AssoReq(seq=1831) -- MitM'ing
	[01:39:19] Real channel : 02:00:00:00:00:00 -> 02:00:00:00:01:00: EAPOL-Msg1(seq=0, replay=1) -- MitM'ing
	[01:39:19] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EAPOL-Msg2(seq=0, replay=1) -- MitM'ing
	[01:39:19] Real channel : 02:00:00:00:00:00 -> 02:00:00:00:01:00: EAPOL-Msg3(seq=1, replay=2) -- MitM'ing
	[01:39:19] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EAPOL-Msg4(seq=1, replay=2) -- MitM'ing
	[01:39:19] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EncData(PN=1, len=126) -- MitM'ing
	[01:39:20] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EncData(PN=2, len=122) -- MitM'ing
	[01:39:20] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EncData(PN=3, len=126) -- MitM'ing
	[01:39:21] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EncData(PN=4, len=126) -- MitM'ing
	[01:39:21] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EncData(PN=5, len=106) -- MitM'ing
	[01:39:21] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EncData(PN=6, len=126) -- MitM'ing
	[01:39:24] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EncData(PN=7, len=106) -- MitM'ing
	^CTraceback (most recent call last):
	  File "/home/mathy/research/wifi/mc-mitm/./mc-mitm.py", line 834, in <module>
		attack.run()
	  File "/home/mathy/research/wifi/mc-mitm/./mc-mitm.py", line 783, in run
		sel = select.select([self.sock_rogue, self.sock_real], [], [], 0.1)
	KeyboardInterrupt
	[23:10:03] Cleaning up ...

	(venv) [root@zbook-mathy mc-mitm]#

