#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from struct import pack, unpack, unpack_from, calcsize
from subprocess import Popen, PIPE, DEVNULL, STDOUT
from os.path import expandvars, dirname, realpath
from os import makedirs, getenv, listdir
from traceback import print_exc
from shutil import copy2, which
from logging import warning
from sys import platform
import gzip

from ..modules._enable_log_mixin import EnableLogMixin, TYPES_FOR_RAW_PACKET_LOGGING
from ..modules.decoded_sibs_dump import DecodedSibsDumper

MODULES_DIR = realpath(dirname(__file__))
SRC_WIRESHARK_PLUGIN_DIR = realpath(MODULES_DIR + '/wireshark_plugin')


try:
    from os import setpgrp, getenv, setresgid, setresuid, setgroups, getgrouplist
    from pwd import getpwuid
    IS_UNIX = True

except Exception:
    IS_UNIX = False

from ..protocol.log_types import *
from ..protocol.gsmtap import *

"""
    This module registers various diag LOG events, and tries to generate a
    PCAP of GSMTAP 2G, 3G, 4G or 5G frames from it.
    
    5G frames shall be decoded from a .PCAP or .DLF file only if
    the QCSuper Wireshark plugin is installed or loaded.
"""

class PcapDumper(DecodedSibsDumper):
    
    def __init__(self, diag_input, pcap_file, reassemble_sibs, decrypt_nas, include_ip_traffic):
        
        self.seen_log_types = set()
        self.log_type_file = open("seen_log_types.txt", "a")
        
        self.pcap_file = pcap_file
        
        """
            Write a PCAP file header - https://wiki.wireshark.org/Development/LibpcapFileFormat#File_Format
        """
        
        if not self.pcap_file.appending_to_file:
            
            self.pcap_file.write(pack('<IHHi4xII',
                0xa1b2c3d4, # PCAP Magic
                2, 4, # Version
                0, # Timezone
                65535, # Max packet length
                228 # LINKTYPE_IPV4 (for GSMTAP)
            ))
        
        self.diag_input = diag_input
        
        self.limit_registered_logs = TYPES_FOR_RAW_PACKET_LOGGING
        
        self.current_rat = None # Radio access technology: "2g", "3g", "4g", "5g"
        
        self.reassemble_sibs = reassemble_sibs
        self.decrypt_nas = decrypt_nas
        self.include_ip_traffic = include_ip_traffic
        
        # Install the QCSuper Lua Wireshark plug-in, except if the
        # corresponding environment variable is set.
        
        self.install_wireshark_plugin()
    
    def install_wireshark_plugin(self): # WIP
        
        # See: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
        # See: https://docs.python.org/3/library/os.path.html#os.path.expandvars
        # See: https://docs.python.org/3/library/sys.html#sys.platform
        
        if getenv('DONT_INSTALL_WIRESHARK_PLUGIN'):
            
            return
        
        if platform in ('win32', 'cygwin'):
            
            DST_WIRESHARK_PLUGIN_DIR = expandvars('%APPDATA%\\Wireshark\\plugins')
        
        else:
            
            DST_WIRESHARK_PLUGIN_DIR = expandvars('$HOME/.local/lib/wireshark/plugins')
        
        if '%' in DST_WIRESHARK_PLUGIN_DIR or '$' in DST_WIRESHARK_PLUGIN_DIR:
            return # Variable expansion did not work
        
        try:
            makedirs(DST_WIRESHARK_PLUGIN_DIR, exist_ok = True)
            
            for file_name in listdir(SRC_WIRESHARK_PLUGIN_DIR):
                
                copy2(SRC_WIRESHARK_PLUGIN_DIR + '/' + file_name,
                    DST_WIRESHARK_PLUGIN_DIR + '/' + file_name)
        
        except OSError:
            return # Could not create or write to the Wireshark plug-in directory, non-fatal
        
    
    """
        Process a single log packet containing raw signalling or data traffic,
        to be encapsulated into GSMTAP and append to the PCAP
    """
    
    def on_log(self, log_type, log_payload, log_header, timestamp = 0):
        
        print(f"[TRACE] Received log_type: {hex(log_type)}")
        
        if log_type not in self.seen_log_types:
            self.seen_log_types.add(log_type)
            self.log_type_file.write(f"{hex(log_type)}\n")
            self.log_type_file.flush()

        packet = None
        
        if log_type == WCDMA_SIGNALLING_MESSAGE: # 0x412f
            
            self.current_rat = '3g'
            
            (channel_type, radio_bearer, length), signalling_message = unpack('<BBH', log_payload[:4]), log_payload[4:]
            
            is_uplink = channel_type in (
                RRCLOG_SIG_UL_CCCH,
                RRCLOG_SIG_UL_DCCH
            )
            
            # GSMTAP definition:
            # - https://github.com/wireshark/wireshark/blob/wireshark-2.5.0/epan/dissectors/packet-gsmtap.h
            # - http://osmocom.org/projects/baseband/wiki/GSMTAP
            
            # RRC channel types:
            # - https://github.com/fgsect/scat/blob/0e1d3a4/parsers/qualcomm/diagwcdmalogparser.py#L259
            
            if channel_type in (254, 255, 0x89, 0xF0, RRCLOG_EXTENSION_SIB, RRCLOG_SIB_CONTAINER):
                return # Frames containing only a MIB or extension SIB, as already present in RRC frames, ignoring
            
            if channel_type >= 0x80: # We are in presence of an explicit ARFCN/PSC
                channel_type -= 0x80
                signalling_message = signalling_message[4:]
            
            packet = signalling_message[:length]
            
            gsmtap_channel_type = {
                RRCLOG_SIG_UL_CCCH: GSMTAP_RRC_SUB_UL_CCCH_Message,
                RRCLOG_SIG_UL_DCCH: GSMTAP_RRC_SUB_UL_DCCH_Message,
                RRCLOG_SIG_DL_CCCH: GSMTAP_RRC_SUB_DL_CCCH_Message,
                RRCLOG_SIG_DL_DCCH: GSMTAP_RRC_SUB_DL_DCCH_Message,
                RRCLOG_SIG_DL_BCCH_BCH: GSMTAP_RRC_SUB_BCCH_BCH_Message,
                RRCLOG_SIG_DL_BCCH_FACH: GSMTAP_RRC_SUB_BCCH_FACH_Message,
                RRCLOG_SIG_DL_PCCH: GSMTAP_RRC_SUB_PCCH_Message,
                RRCLOG_SIG_DL_MCCH: GSMTAP_RRC_SUB_MCCH_Message,
                RRCLOG_SIG_DL_MSCH: GSMTAP_RRC_SUB_MSCH_Message
            }.get(channel_type)
            
            if gsmtap_channel_type is None:
                
                warning('Unknown log type received for WCDMA_SIGNALLING_MESSAGE: %d' % channel_type)
                return
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_UMTS_RRC, gsmtap_channel_type, packet, is_uplink)
        
        elif log_type == LOG_GSM_RR_SIGNALING_MESSAGE_C: # 0x512f
            
            self.current_rat = '2g'
            
            (channel_type, message_type, length), signalling_message = unpack('<BBB', log_payload[:3]), log_payload[3:]
            
            packet = signalling_message[:length]
            
            is_uplink = not bool(channel_type & 0x80)
            
            # GSMTAP definition:
            # - https://github.com/wireshark/wireshark/blob/wireshark-2.5.0/epan/dissectors/packet-gsmtap.h
            # - http://osmocom.org/projects/baseband/wiki/GSMTAP
            
            gsmtap_channel_type = {
                DCCH: GSMTAP_CHANNEL_SDCCH,
                BCCH: GSMTAP_CHANNEL_BCCH,
                L2_RACH: GSMTAP_CHANNEL_RACH,
                CCCH: GSMTAP_CHANNEL_CCCH,
                SACCH: GSMTAP_CHANNEL_SDCCH | GSMTAP_CHANNEL_ACCH,
                SDCCH: GSMTAP_CHANNEL_SDCCH,
                FACCH_F: GSMTAP_CHANNEL_TCH_F | GSMTAP_CHANNEL_ACCH,
                FACCH_H: GSMTAP_CHANNEL_TCH_F | GSMTAP_CHANNEL_ACCH,
                L2_RACH_WITH_NO_DELAY: GSMTAP_CHANNEL_RACH
            }.get(channel_type & 0x7f)
            
            if gsmtap_channel_type is None:
                
                warning('Unknown log type received for LOG_GSM_RR_SIGNALING_MESSAGE_C: %d' % channel_type)
                return
            
            # Diag is delivering us L3 data, but GSMTAP will want L2 for most
            # channels (including a LAPDm header that we don't have), the
            # workaround for this is to set the interface type to A-bis.
            
            # Other channels that include just a L2 pseudo length before their
            # protocol discriminator will have it removed.
            
            interface_type = GSMTAP_TYPE_ABIS
            
            if gsmtap_channel_type in (GSMTAP_CHANNEL_BCCH, GSMTAP_CHANNEL_CCCH):
                
                packet = packet[1:]
            
            packet = build_gsmtap_ip(interface_type, gsmtap_channel_type, packet, is_uplink)
        
        elif log_type == LOG_GPRS_MAC_SIGNALLING_MESSAGE_C: # 0x5226
            
            (channel_type, message_type, length), signalling_message = unpack('<BBB', log_payload[:3]), log_payload[3:]
            
            if message_type == PACKET_CHANNEL_REQUEST:
                return # "Internal use", discard
            
            # This contains the whole RLC/MAC header
            
            PAYLOAD_TYPE_CTRL_NO_OPT_OCTET = 1 # Protocol constant from Wireshark
            packet = bytes([PAYLOAD_TYPE_CTRL_NO_OPT_OCTET << 6, *signalling_message[:length]])
            
            is_uplink = not bool(channel_type & 0x80)
            
            if channel_type == 255:
                return
            
            gsmtap_channel_type = {
                PACCH_RRBP_CHANNEL: GSMTAP_CHANNEL_PACCH,
                UL_PACCH_CHANNEL: GSMTAP_CHANNEL_PACCH,
                DL_PACCH_CHANNEL: GSMTAP_CHANNEL_PACCH
            }.get(channel_type)
            
            if gsmtap_channel_type is None:
                
                warning('Unknown log type received for LOG_GPRS_MAC_SIGNALLING_MESSAGE_C: %d' % channel_type)
                return
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_UM, gsmtap_channel_type, packet, is_uplink)
        
        elif log_type == LOG_LTE_RRC_OTA_MSG_LOG_C: # 0xb0c0
            
            self.current_rat = '4g'
            
            # Interesting structures are defined:
            # - By MobileInsight here: https://github.com/mobile-insight/mobileinsight-core/blob/v3.2.0/dm_collector_c/log_packet.h#L200
            # - By Moiji diag-parser here: https://github.com/moiji-mobile/diag-parser/blob/master/diag_input.c#L206
            
            # Parse base header
            
            (ext_header_ver, rrc_rel, rrc_ver, bearer_id, phy_cellid), ext_header = unpack('<BBBBH', log_payload[:6]), log_payload[6:]
            
            if ext_header_ver >= 25: # Handle post-NR releases
                (ext_header_ver, rrc_rel, rrc_ver, nc_rrc_rel, bearer_id, phy_cellid), ext_header = unpack('<BBBHBH', log_payload[:8]), log_payload[8:]
            
            # Parse extended header
            
            freq_type = 'H' if ext_header_ver < 8 else 'I'
            
            header_spec = '<' + freq_type + 'HBH'
            
            if unpack_from('<H', ext_header, calcsize(header_spec) - 2)[0] != len(ext_header) - calcsize(header_spec): # SIB mask is present
                
                header_spec = '<' + freq_type + 'HB4xH'
            
            (freq, sfn, channel_type, length), packet = unpack_from(header_spec, ext_header), ext_header[calcsize(header_spec):]
            
            # GSMTAP definition:
            # - https://github.com/wireshark/wireshark/blob/wireshark-2.5.0/epan/dissectors/packet-gsmtap.h
            # - http://osmocom.org/projects/baseband/wiki/GSMTAP
            
            if channel_type in (254, 255):
                return # Frames containing only a MIB or extension SIB, as already present in RRC frames, ignoring
            
            if LTE_UL_DCCH_NB < channel_type <= LTE_UL_DCCH_NB + 9:
                channel_type -= 9

            
            # See here for LTE channel constants (they heavily depend on baseband
            # versions): https://github.com/fgsect/scat/blob/1d5b81/parsers/qualcomm/diagltelogparser.py#L1207
            
            channel_lookup_table = {
                LTE_BCCH_BCH_NB: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_NB,
                LTE_BCCH_DL_SCH_NB: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_NB,
                LTE_PCCH_NB: GSMTAP_LTE_RRC_SUB_PCCH_Message_NB,
                LTE_DL_CCCH_NB: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message_NB,
                LTE_DL_DCCH_NB: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message_NB,
                LTE_UL_CCCH_NB: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message_NB,
                LTE_UL_DCCH_NB: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message_NB,
            }
            
            # The v9 channel type values don't overlap a lot with other
            # existing values as they start at "8", so handle these in
            # all case and allow these to be erased with other values
            # subsequently
                        
            channel_lookup_table.update({
                LTE_BCCH_BCH_v9: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                LTE_BCCH_DL_SCH_v9: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                LTE_MCCH_v9: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                LTE_PCCH_v9: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                LTE_DL_CCCH_v9: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                LTE_DL_DCCH_v9: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                LTE_UL_CCCH_v9: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                LTE_UL_DCCH_v9: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
            })
        
            if ext_header_ver in (14, 15, 16, 20, 24, 25):

                channel_lookup_table.update({
                    LTE_BCCH_BCH_v14: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                    LTE_BCCH_DL_SCH_v14: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                    LTE_MCCH_v14: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                    LTE_PCCH_v14: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                    LTE_DL_CCCH_v14: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                    LTE_DL_DCCH_v14: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                    LTE_UL_CCCH_v14: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                    LTE_UL_DCCH_v14: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                })
            
            elif ext_header_ver == 19 or ext_header_ver >= 26:
                
                channel_lookup_table.update({
                    LTE_BCCH_BCH_v19: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                    LTE_BCCH_DL_SCH_v19: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                    LTE_MCCH_v19: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                    LTE_PCCH_v19: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                    LTE_DL_CCCH_v19: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                    LTE_DL_DCCH_v19: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                    LTE_UL_CCCH_v19: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                    LTE_UL_DCCH_v19: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                })

            elif ext_header_ver not in (9, 12):
            
                channel_lookup_table.update({
                    LTE_BCCH_BCH_v0: GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
                    LTE_BCCH_DL_SCH_v0: GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
                    LTE_MCCH_v0: GSMTAP_LTE_RRC_SUB_MCCH_Message,
                    LTE_PCCH_v0: GSMTAP_LTE_RRC_SUB_PCCH_Message,
                    LTE_DL_CCCH_v0: GSMTAP_LTE_RRC_SUB_DL_CCCH_Message,
                    LTE_DL_DCCH_v0: GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
                    LTE_UL_CCCH_v0: GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                    LTE_UL_DCCH_v0: GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                })
                
            gsmtap_channel_type = channel_lookup_table.get(channel_type)
            
            is_uplink = gsmtap_channel_type in (
                GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
                GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
                GSMTAP_LTE_RRC_SUB_UL_CCCH_Message_NB,
                GSMTAP_LTE_RRC_SUB_UL_DCCH_Message_NB,
            )
            
            if gsmtap_channel_type is None:
                
                warning('Unknown log type received for LOG_LTE_RRC_OTA_MSG_LOG_C version %d: %d' % (
                    ext_header_ver, channel_type))
                return
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_LTE_RRC, gsmtap_channel_type, packet, is_uplink)
        
        elif self.decrypt_nas and log_type in (
            LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
            LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,
            LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
            LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C
        ): # 4G unencrypted NAS
            
            # Header source: https://github.com/mobile-insight/mobileinsight-core/blob/v3.2.0/dm_collector_c/log_packet.h#L274
            
            (ext_header_ver, rrc_rel, rrc_ver_minor, rrc_ver_major), signalling_message = unpack('<BBBB', log_payload[:4]), log_payload[4:]
            
            is_uplink = log_type in (LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C, LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C)
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_LTE_NAS, GSMTAP_LTE_NAS_PLAIN, signalling_message, is_uplink)
        
        elif self.include_ip_traffic and log_type == LOG_DATA_PROTOCOL_LOGGING_C: # 0x11eb - IPv4 user-plane data
            
            packet = log_payload[8:]
        
        elif log_type == LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C: # 0x713a - 2G/3G DTAP from NAS
            
            if self.current_rat != '2g': # Not needed in 3G, where this is already embedded in RRC
                
                return
            
            # Header source: https://github.com/mobile-insight/mobileinsight-core/blob/v3.2.0/dm_collector_c/log_packet.h#L274
            
            (is_uplink, length), signalling_message = unpack('<BI', log_payload[:5]), log_payload[5:]
            
            packet = signalling_message[:length]
            
            is_uplink = bool(is_uplink)
            
            packet = build_gsmtap_ip(GSMTAP_TYPE_ABIS, GSMTAP_CHANNEL_SDCCH, signalling_message, is_uplink)
        

        elif log_type in (
                        0x11EB, 0x1572, 0x1573, 0x1574, 0x1575, 0x1576, 0x1577, 0x1578,
                        0x1579, 0x189E, 0x1951, 0x1375, 0x1376, 0x1D15, 0x1E1E, 0x109C,
                        0x109D, 0x1113, 0x1114, 0x1115, 0x1123, 0x1124, 0x1125, 0x1133,
                        0x1134, 0x1135, 0x1143, 0x1144, 0x1145, 0x1273, 0x12C1, 0x132B,
                        0x132C, 0x132D, 0x132E, 0x1335, 0x1336, 0x1337, 0x1338, 0x1339,
                        0x133A, 0x1343, 0x134F, 0x1356, 0x135A, 0x135B, 0x135C, 0x138E,
                        0x138F, 0x1390, 0x1391, 0x1392, 0x1393, 0x1394, 0x1395, 0x1396,
                        0x1397, 0x1398, 0x1399, 0x139A, 0x139B, 0x139C, 0x139D, 0x139E,
                        0x139F, 0x13A0, 0x13A1, 0x13A2, 0x13A3, 0x13AF, 0x145B, 0x1486,
                        0x14C2, 0x14CF, 0x157A, 0x157B, 0x157C, 0x157D, 0x157E, 0x157F,
                        0x1580, 0x1581, 0x1582, 0x1583, 0x1584, 0x1585, 0x1588, 0x412F/000/000,
                        0x412F/000/1, 0x412F/000/2, 0x412F/1/000, 0x412F/1/1,
                        0x412F/1/2, 0x412F/1/3, 0x412F/1/4, 0x412F/1/5,
                        0x412F/1/6, 0x412F/1/7, 0x412F/1/8, 0x412F/1/9,
                        0x412F/1/10, 0x412F/1/11, 0x412F/1/12, 0x412F/1/13,
                        0x412F/1/14, 0x412F/1/15, 0x412F/1/16, 0x412F/1/17,
                        0x412F/1/18, 0x412F/1/19, 0x412F/1/20, 0x412F/1/21,
                        0x412F/1/22, 0x412F/1/23, 0x412F/1/24, 0x412F/1/25,
                        0x412F/1/26, 0x412F/1/27, 0x412F/1/28, 0x412F/1/29,
                        0x412F/1/30, 0x412F/2/000, 0x412F/2/1, 0x412F/2/2,
                        0x412F/2/3, 0x412F/2/4, 0x412F/3/000, 0x412F/3/1,
                        0x412F/3/2, 0x412F/3/3, 0x412F/3/4, 0x412F/3/5,
                        0x412F/3/6, 0x412F/3/7, 0x412F/3/8, 0x412F/3/9,
                        0x412F/3/10, 0x412F/3/11, 0x412F/3/12, 0x412F/3/13,
                        0x412F/3/14, 0x412F/3/15, 0x412F/3/16, 0x412F/3/17,
                        0x412F/3/18, 0x412F/3/19, 0x412F/3/20, 0x412F/3/21,
                        0x412F/3/22, 0x412F/3/23, 0x412F/3/24, 0x412F/3/25,
                        0x412F/3/26, 0x412F/4/000, 0x412F/4/1, 0x412F/4/2,
                        0x412F/4/3, 0x412F/4/4, 0x412F/4/5, 0x412F/4/6,
                        0x412F/4/7, 0x412F/4/8, 0x412F/4/9, 0x412F/4/10,
                        0x412F/5/000/000, 0x412F/5/000/1, 0x412F/5/000/2,0x412F/5/000/3, 0x412F/5/000/4,
                        0x412F/5/000/5, 0x412F/5/000/6, 0x412F/5/000/7, 0x412F/5/000/8, 0x412F/5/000/9,
                        0x412F/5/000/10, 0x412F/5/1, 0x412F/6/000, 0x412F/7/000, 0x412F/7/1, 0x412F/7/2,
                        0x412F/7/3, 0x412F/7/4, 0x412F/7/5, 0x412F/7/6, 0x412F/8/000, 0x412F/254/000,
                        0x412F/254/1, 0x412F/254/2, 0x412F/254/3, 0x412F/254/4, 0x412F/254/5, 0x412F/254/6,
                        0x412F/254/7, 0x412F/254/8, 0x412F/254/9, 0x412F/254/10, 0x412F/254/11, 0x412F/254/12,
                        0x412F/254/13, 0x412F/254/14, 0x412F/254/15, 0x412F/254/16, 0x412F/254/17, 0x412F/254/18,
                        0x412F/254/19, 0x412F/254/20, 0x412F/254/21, 0x412F/254/22, 0x412F/254/23, 0x412F/254/24,
                        0x412F/254/25, 0x412F/254/26, 0x412F/254/27, 0x412F/254/28, 0x412F/254/29, 0x412F/254/30,
                        0x412F/255/000, 0x412F/255/1, 0x412F/255/2, 0x412F/255/3, 0x412F/255/4, 0x412F/255/5,
                        0x412F/255/6, 0x412F/255/7, 0x412F/255/8, 0x412F/255/9, 0x412F/255/10, 0x412F/255/11,
                        0x412F/255/12, 0x412F/255/13, 0x412F/255/14, 0x412F/255/15, 0x412F/255/16, 0x412F/255/17,
                        0x412F/255/18, 0x412F/255/19, 0x412F/255/20, 0x412F/255/21, 0x412F/255/22, 0x412F/255/23,
                        0x412F/255/24, 0x412F/255/25, 0x412F/255/26, 0x412F/255/27, 0x412F/255/28, 0x412F/255/29,
                        0x412F/255/30, 0x4132, 0x4133, 0x4134, 0x4135, 0x413B, 0x413C, 0x4145, 0x4146, 0x4161, 0x4162,
                        0x4168, 0x4169, 0x4200, 0x4206, 0x4207, 0x4208, 0x420B, 0x4210, 0x5064, 0x506C, 0x5079, 0x512F/000/14,
                        0x512F/000/15, 0x512F/000/17, 0x512F/000/18, 0x512F/000/22, 0x512F/000/23, 0x512F/000/38,
                        0x512F/000/39, 0x512F/000/40, 0x512F/000/41, 0x512F/000/44, 0x512F/000/47, 0x512F/000/49,
                        0x512F/000/50, 0x512F/000/51, 0x512F/000/52, 0x512F/000/56, 0x512F/000/60, 0x512F/000/72,
                        0x512F/000/74, 0x512F/000/96, 0x512F/000/98, 0x512F/2/14, 0x512F/2/18, 0x512F/2/38,
                        0x512F/4/14, 0x512F/4/18, 0x512F/4/21, 0x512F/4/38, 0x512F/4/54, 0x512F/5/14,
                        0x512F/5/18, 0x512F/5/38, 0x512F/6/14, 0x512F/6/18, 0x512F/6/38, 0x512F/128/8,
                        0x512F/128/9, 0x512F/128/10, 0x512F/128/13, 0x512F/128/14, 0x512F/128/16, 0x512F/128/18,
                        0x512F/128/19, 0x512F/128/20, 0x512F/128/32, 0x512F/128/35, 0x512F/128/42, 0x512F/128/43,
                        0x512F/128/45, 0x512F/128/46, 0x512F/128/48, 0x512F/128/53, 0x512F/128/56, 0x512F/128/59,
                        0x512F/128/73, 0x512F/128/75, 0x512F/128/76, 0x512F/128/77, 0x512F/128/97, 0x512F/128/99,
                        0x512F/128/100, 0x512F/128/130, 0x512F/129/000, 0x512F/129/2, 0x512F/129/3, 0x512F/129/4,
                        0x512F/129/7, 0x512F/129/9, 0x512F/129/14, 0x512F/129/18, 0x512F/129/24, 0x512F/129/25,
                        0x512F/129/26, 0x512F/129/27, 0x512F/129/28, 0x512F/129/31, 0x512F/129/32, 0x512F/129/61,
                        0x512F/129/62, 0x512F/129/64, 0x512F/129/65, 0x512F/129/66, 0x512F/131/9, 0x512F/131/14,
                        0x512F/131/18, 0x512F/131/32, 0x512F/131/33, 0x512F/131/34, 0x512F/131/36, 0x512F/131/57,
                        0x512F/131/58, 0x512F/131/63, 0x512F/132/5, 0x512F/132/6, 0x512F/132/9, 0x512F/132/14,
                        0x512F/132/18, 0x512F/132/29, 0x512F/132/30, 0x512F/132/32, 0x512F/132/55, 0x512F/133/9,
                        0x512F/133/14, 0x512F/133/18, 0x512F/133/32, 0x512F/134/9, 0x512F/134/14, 0x512F/134/18,
                        0x512F/134/32, 0x5130, 0x5134, 0x5137, 0x51F4, 0x51F5, 0x51F6, 0x51F7, 0x51F8, 0x51F9, 0x51FB,
                        0x51FC, 0x5205, 0x5206, 0x5209, 0x520F, 0x5210, 0x5211, 0x5217, 0x5218, 0x5219, 0x521C, 0x521D,
                        0x5220, 0x5221, 0x5226/3/000, 0x5226/3/1, 0x5226/3/2, 0x5226/3/3, 0x5226/3/4,
                        0x5226/3/5, 0x5226/3/6, 0x5226/3/7, 0x5226/3/8, 0x5226/3/9, 0x5226/3/10,
                        0x5226/3/11, 0x5226/4/000, 0x5226/4/1, 0x5226/4/2, 0x5226/4/3, 0x5226/4/4,
                        0x5226/4/5, 0x5226/4/6, 0x5226/4/7, 0x5226/4/8, 0x5226/4/9, 0x5226/4/10,
                        0x5226/4/11, 0x5226/129/1, 0x5226/129/2, 0x5226/129/3, 0x5226/129/4, 0x5226/129/6,
                        0x5226/129/10, 0x5226/129/33, 0x5226/129/34, 0x5226/129/36, 0x5226/129/37, 0x5226/130/48,
                        0x5226/130/49, 0x5226/130/50, 0x5226/130/51, 0x5226/130/52, 0x5226/130/53, 0x5226/130/54,
                        0x5226/130/55, 0x5226/130/56, 0x5226/130/57, 0x5226/130/60, 0x5226/130/61, 0x5226/131/1,
                        0x5226/131/2, 0x5226/131/3, 0x5226/131/4, 0x5226/131/5, 0x5226/131/7, 0x5226/131/8,
                        0x5226/131/9, 0x5226/131/10, 0x5226/131/33, 0x5226/131/34, 0x5226/131/35, 0x5226/131/37,
                        0x5226/131/48, 0x5226/131/49, 0x5226/131/50, 0x5226/131/51, 0x5226/131/52, 0x5226/131/53,
                        0x5226/131/55, 0x5226/131/56, 0x5226/131/57, 0x5226/131/58, 0x5226/131/60, 0x5226/131/61,
                        0x5226/131/62, 0x5228, 0x5229, 0x522A, 0x522B, 0x522C, 0x522D, 0x5230/000/1, 0x5230/000/3,
                        0x5230/000/5, 0x5230/000/6, 0x5230/000/8, 0x5230/000/10, 0x5230/000/12, 0x5230/000/17,
                        0x5230/000/19, 0x5230/000/22, 0x5230/000/28, 0x5230/000/32, 0x5230/000/65, 0x5230/000/69,
                        0x5230/000/70, 0x5230/000/71, 0x5230/000/73, 0x5230/000/74, 0x5230/000/77, 0x5230/000/85,
                        0x5230/1/2, 0x5230/1/4, 0x5230/1/5, 0x5230/1/6, 0x5230/1/9, 0x5230/1/11,
                        0x5230/1/13, 0x5230/1/14, 0x5230/1/16, 0x5230/1/18, 0x5230/1/20, 0x5230/1/21,
                        0x5230/1/32, 0x5230/1/33, 0x5230/1/66, 0x5230/1/67, 0x5230/1/68, 0x5230/1/70,
                        0x5230/1/71, 0x5230/1/72, 0x5230/1/75, 0x5230/1/76, 0x5230/1/78, 0x5230/1/79,
                        0x5230/1/85, 0x5245, 0x524D, 0x525B, 0x5262, 0x5263, 0x71, 0x713A/3/1, 0x713A/3/2,
                        0x713A/3/3, 0x713A/3/4, 0x713A/3/5, 0x713A/3/6, 0x713A/3/7, 0x713A/3/8,
                        0x713A/3/9, 0x713A/3/11, 0x713A/3/14, 0x713A/3/15, 0x713A/3/16, 0x713A/3/19,
                        0x713A/3/23, 0x713A/3/24, 0x713A/3/25, 0x713A/3/26, 0x713A/3/28, 0x713A/3/29,
                        0x713A/3/30, 0x713A/3/31, 0x713A/3/37, 0x713A/3/42, 0x713A/3/45, 0x713A/3/49,
                        0x713A/3/50, 0x713A/3/52, 0x713A/3/53, 0x713A/3/54, 0x713A/3/55, 0x713A/3/57,
                        0x713A/3/58, 0x713A/3/61, 0x713A/3/62, 0x713A/5/1, 0x713A/5/2, 0x713A/5/4,
                        0x713A/5/8, 0x713A/5/17, 0x713A/5/18, 0x713A/5/20, 0x713A/5/24, 0x713A/5/25,
                        0x713A/5/26, 0x713A/5/27, 0x713A/5/28, 0x713A/5/33, 0x713A/5/34, 0x713A/5/35,
                        0x713A/5/36, 0x713A/5/37, 0x713A/5/40, 0x713A/5/41, 0x713A/5/48, 0x713A/5/49,
                        0x713A/5/50, 0x713A/6/000, 0x713A/6/2, 0x713A/6/3, 0x713A/6/4, 0x713A/6/7,
                        0x713A/6/8, 0x713A/6/9, 0x713A/6/10, 0x713A/6/13, 0x713A/6/14, 0x713A/6/15,
                        0x713A/6/16, 0x713A/6/17, 0x713A/6/18, 0x713A/6/19, 0x713A/6/20, 0x713A/6/21,
                        0x713A/6/22, 0x713A/6/23, 0x713A/6/24, 0x713A/6/25, 0x713A/6/26, 0x713A/6/27,
                        0x713A/6/28, 0x713A/6/31, 0x713A/6/32, 0x713A/6/33, 0x713A/6/34, 0x713A/6/35,
                        0x713A/6/36, 0x713A/6/38, 0x713A/6/39, 0x713A/6/40, 0x713A/6/41, 0x713A/6/42,
                        0x713A/6/43, 0x713A/6/44, 0x713A/6/45, 0x713A/6/46, 0x713A/6/47, 0x713A/6/48,
                        0x713A/6/49, 0x713A/6/50, 0x713A/6/51, 0x713A/6/52, 0x713A/6/53, 0x713A/6/54,
                        0x713A/6/55, 0x713A/6/56, 0x713A/6/57, 0x713A/6/58, 0x713A/6/59, 0x713A/6/60,
                        0x713A/6/61, 0x713A/6/62, 0x713A/6/63, 0x713A/6/64, 0x713A/6/65, 0x713A/6/66,
                        0x713A/6/72, 0x713A/6/73, 0x713A/6/74, 0x713A/6/75, 0x713A/6/76, 0x713A/6/77,
                        0x713A/6/96, 0x713A/6/98, 0x713A/6/99, 0x713A/6/100, 0x713A/8/1, 0x713A/8/2,
                        0x713A/8/3, 0x713A/8/4, 0x713A/8/5, 0x713A/8/6, 0x713A/8/8, 0x713A/8/9,
                        0x713A/8/10, 0x713A/8/11, 0x713A/8/12, 0x713A/8/13, 0x713A/8/14, 0x713A/8/16,
                        0x713A/8/17, 0x713A/8/18, 0x713A/8/19, 0x713A/8/20, 0x713A/8/21, 0x713A/8/22,
                        0x713A/8/28, 0x713A/8/32, 0x713A/8/33, 0x713A/9/1, 0x713A/9/4, 0x713A/9/16,
                        0x713A/10/65, 0x713A/10/66, 0x713A/10/67, 0x713A/10/68, 0x713A/10/69, 0x713A/10/70,
                        0x713A/10/71, 0x713A/10/72, 0x713A/10/73, 0x713A/10/74, 0x713A/10/75, 0x713A/10/76,
                        0x713A/10/77, 0x713A/10/78, 0x713A/10/79, 0x713A/10/85, 0x713A/11/42, 0x713A/11/58,
                        0x713A/11/59, 0x7200, 0x7201, 0x7202, 0x7203, 0x7204, 0x7205, 0x7206, 0x7207, 0x7208, 0x7209,
                        0x720A, 0x720C, 0x720D, 0x7211, 0x7212, 0x7219, 0x721B, 0x721D, 0x721E, 0x721F, 0x7220, 0x7221,
                        0x7222, 0x7230, 0x7231, 0x7232, 0x725A, 0x725B, 0x725C, 0x725D, 0x725E, 0x725F, 0x7264, 0x7265,
                        0x7266, 0x7267, 0x726D, 0x72C8, 0x72C9, 0x72CA, 0x72CB, 0x72CC, 0x72CD, 0x72CE, 0x72CF, 0x72D0,
                        0x7B3A/8/1, 0x7B3A/8/2, 0x7B3A/8/3, 0x7B3A/8/4, 0x7B3A/8/5, 0x7B3A/8/6,
                        0x7B3A/8/8, 0x7B3A/8/9, 0x7B3A/8/10, 0x7B3A/8/11, 0x7B3A/8/12, 0x7B3A/8/13,
                        0x7B3A/8/14, 0x7B3A/8/16, 0x7B3A/8/17, 0x7B3A/8/18, 0x7B3A/8/19, 0x7B3A/8/20,
                        0x7B3A/8/21, 0x7B3A/8/22, 0x7B3A/8/28, 0x7B3A/8/32, 0x7B3A/8/33, 0x7B3A/10/65,
                        0x7B3A/10/66, 0x7B3A/10/67, 0x7B3A/10/68, 0x7B3A/10/69, 0x7B3A/10/70, 0x7B3A/10/71,
                        0x7B3A/10/72, 0x7B3A/10/73, 0x7B3A/10/74, 0x7B3A/10/75, 0x7B3A/10/76, 0x7B3A/10/77,
                        0x7B3A/10/78, 0x7B3A/10/79, 0x7B3A/10/85, 0xB081, 0xB082, 0xB083, 0xB084, 0xB085, 0xB086,
                        0xB087, 0xB088, 0xB089, 0xB091, 0xB092, 0xB093, 0xB094, 0xB095, 0xB096, 0xB097, 0xB098, 0xB099,
                        0xB0A0, 0xB0A1, 0xB0A2, 0xB0A3, 0xB0A4, 0xB0B0, 0xB0B1, 0xB0B2, 0xB0B3, 0xB0B4, 0xB0E2, 0xB0E3,
                        0xB0EC, 0xB0ED, ):
            
            print(f"[DEBUG] SimCom log type {hex(log_type)} received, length={len(log_payload)}")

            # SimCom log types - treat as raw IP or diagnostic payload
            if log_type == 0x11EB:
                # Skip 8-byte header for IP payloads
                packet = log_payload[8:]
                interface_type = GSMTAP_TYPE_UM
                channel_type = GSMTAP_CHANNEL_SDCCH
            else:
                packet = log_payload
                interface_type = GSMTAP_TYPE_UM
                channel_type = GSMTAP_CHANNEL_SDCCH  # You can customize this per log type if needed
            
            is_uplink = False  # Adjust if you can infer direction
            packet = build_gsmtap_ip(interface_type, channel_type, packet, is_uplink)

       
        elif log_type == LOG_NR_RRC_OTA_MSG_LOG_C: # LOG_NR_RRC_OTA_MSG_LOG_C = 0xb821
            
            # WIP
            
            self.current_rat = '5g'
        
            packet = build_nr_rrc_log_ip(log_payload)
            
        if packet:
            
            try:
                
                self.pcap_file.write(pack('<IIII',
                    int(timestamp),
                    int((timestamp * 1000000) % 1000000),
                    len(packet),
                    len(packet)
                ) + packet)
            
            except BrokenPipeError:
                
                self.diag_input.remove_module(self)
        
        # Also write a reassembled 3G SIB if present
        
        if self.reassemble_sibs:
            DecodedSibsDumper.on_log(self, log_type, log_payload, log_header, timestamp)
    
    """
        Callback to the be called by the inherited "DecodedSibsDumper" class
        if the user has passed the --reassemble-sibs argument.
        
        The --reassemble-sibs argument will reassemble SIBs into individual
        GSMTAP packets so that Wireshark can process them (it currently
        can't when embedded into RRC frames).
    """
    
    def on_decoded_sib(self, sib_type, sib_dict, sib_bytes, rrc_sfn, timestamp):
        
        packet = sib_bytes
        
        is_uplink = False
        
        gsmtap_channel_type = {
            'masterInformationBlock': GSMTAP_RRC_SUB_MasterInformationBlock,
            'systemInformationBlockType1': GSMTAP_RRC_SUB_SysInfoType1,
            'systemInformationBlockType2': GSMTAP_RRC_SUB_SysInfoType2,
            'systemInformationBlockType3': GSMTAP_RRC_SUB_SysInfoType3,
            'systemInformationBlockType4': GSMTAP_RRC_SUB_SysInfoType4,
            'systemInformationBlockType5': GSMTAP_RRC_SUB_SysInfoType5,
            'systemInformationBlockType6': GSMTAP_RRC_SUB_SysInfoType6,
            'systemInformationBlockType7': GSMTAP_RRC_SUB_SysInfoType7,
            'systemInformationBlockType11': GSMTAP_RRC_SUB_SysInfoType11,
            'systemInformationBlockType12': GSMTAP_RRC_SUB_SysInfoType12,
            'systemInformationBlockType13': GSMTAP_RRC_SUB_SysInfoType13,
            'systemInformationBlockType13-1': GSMTAP_RRC_SUB_SysInfoType13_1,
            'systemInformationBlockType13-2': GSMTAP_RRC_SUB_SysInfoType13_2,
            'systemInformationBlockType13-3': GSMTAP_RRC_SUB_SysInfoType13_3,
            'systemInformationBlockType13-4': GSMTAP_RRC_SUB_SysInfoType13_4,
            'systemInformationBlockType14': GSMTAP_RRC_SUB_SysInfoType14,
            'systemInformationBlockType15': GSMTAP_RRC_SUB_SysInfoType15,
            'systemInformationBlockType15-1': GSMTAP_RRC_SUB_SysInfoType15_1,
            'systemInformationBlockType15-2': GSMTAP_RRC_SUB_SysInfoType15_2,
            'systemInformationBlockType15-3': GSMTAP_RRC_SUB_SysInfoType15_3,
            'systemInformationBlockType16': GSMTAP_RRC_SUB_SysInfoType16,
            'systemInformationBlockType17': GSMTAP_RRC_SUB_SysInfoType17,
            'systemInformationBlockType15-4': GSMTAP_RRC_SUB_SysInfoType15_4,
            'systemInformationBlockType18': GSMTAP_RRC_SUB_SysInfoType18,
            'schedulingBlock1': GSMTAP_RRC_SUB_SysInfoTypeSB1,
            'schedulingBlock2': GSMTAP_RRC_SUB_SysInfoTypeSB2,
            'systemInformationBlockType15-5': GSMTAP_RRC_SUB_SysInfoType15_5,
            'systemInformationBlockType5bis': GSMTAP_RRC_SUB_SysInfoType5bis,
            'systemInfoType11bis': GSMTAP_RRC_SUB_SysInfoType11bis,
            'systemInfoType15bis': GSMTAP_RRC_SUB_SysInfoType15bis,
            'systemInfoType15-1bis': GSMTAP_RRC_SUB_SysInfoType15_1bis,
            'systemInfoType15-2bis': GSMTAP_RRC_SUB_SysInfoType15_2bis,
            'systemInfoType15-3bis': GSMTAP_RRC_SUB_SysInfoType15_3bis,
            'systemInfoType15-6': GSMTAP_RRC_SUB_SysInfoType15_6,
            'systemInfoType15-7': GSMTAP_RRC_SUB_SysInfoType15_7,
            'systemInfoType15-8': GSMTAP_RRC_SUB_SysInfoType15_8,
            'systemInfoType19': GSMTAP_RRC_SUB_SysInfoType19,
            'systemInfoType15-2ter': GSMTAP_RRC_SUB_SysInfoType15_2ter,
            'systemInfoType20': GSMTAP_RRC_SUB_SysInfoType20,
            'systemInfoType21': GSMTAP_RRC_SUB_SysInfoType21,
            'systemInfoType22': GSMTAP_RRC_SUB_SysInfoType22
        }[sib_type]
            
        packet = build_gsmtap_ip(GSMTAP_TYPE_UMTS_RRC, gsmtap_channel_type, packet, is_uplink)
        
        assert len(packet) <= 65535
        
        try:
        
            self.pcap_file.write(pack('<IIII',
                int(timestamp),
                int((timestamp * 1000000) % 1000000),
                len(packet),
                len(packet)
            ) + packet)
        
        except BrokenPipeError:
            
            self.diag_input.remove_module(self)

    def on_sib_decoding_error(self, decoding_error):
        
        pass
    
    def __del__(self):
        
        if hasattr(self, 'log_type_file'):
            self.log_type_file.close()
        
        if getattr(self, 'pcap_file', None):
            self.pcap_file.close()


"""
    This is the same module, except that il will launch directly a FIFO to
    Wireshark rather than write the PCAP to a file
"""

class WiresharkLive(PcapDumper):

    def __init__(self, diag_input, reassemble_sibs, decrypt_nas, include_ip_traffic):
        
        wireshark = (
            which('C:\\Program Files\\Wireshark\\Wireshark.exe') or
            which('C:\\Program Files (x86)\\Wireshark\\Wireshark.exe') or
            which('wireshark') or
            which('wireshark-gtk')
        )
        
        if not wireshark:
            
            raise Exception('Could not find Wireshark in $PATH')
        
        if not IS_UNIX:
            
            self.detach_process = None
        
        wireshark_pipe = Popen([wireshark, '-k', '-i', '-'],
            stdin = PIPE, stdout = DEVNULL, stderr = STDOUT,
            preexec_fn = self.detach_process,
            bufsize = 0
        ).stdin
        
        wireshark_pipe.appending_to_file = False
        
        super().__init__(diag_input, wireshark_pipe, reassemble_sibs, decrypt_nas, include_ip_traffic)
    
    """
        Executed when we launch a Wireshark process, after fork()
    """
    
    def detach_process(self):
        
        try:
            
            # Don't be hit by CTRL+C
            
            setpgrp()
            
            # Drop privileges if needed
            
            uid, gid = getenv('SUDO_UID'), getenv('SUDO_GID')
            
            if uid and gid:
                
                uid, gid = int(uid), int(gid)

                setgroups(getgrouplist(getpwuid(uid).pw_name, gid))

                setresgid(gid, gid, -1)
                
                setresuid(uid, uid, -1)
        
        except Exception:
            
            print_exc()

