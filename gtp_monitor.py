from scapy.all import *
from scapy.contrib import gtp
import random
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-l","--loop", help="Loop the script for x times", type=int)
parser.add_argument("-G", "--GGSN", help="Choose which GGSN to monitor", type=str)
args = parser.parse_args()

def main(loop=1, GGSN='GPHPT02'):

	for x in xrange(loop):
        	ggsn = {'10.221.48.252': 'GPHPT01',
			'10.221.58.214': 'GPHPT02'}
		
		GGSN_dict = { "GPHPT01": '10.221.48.252',
			      "GPHPT02": '10.221.58.214'}

		IP_GGSN = GGSN_dict.get(GGSN)
		fake_TEICI =  0xFFFFF
		IMSI_Rand_Part = str(random.randint(0000000000,9999999999)).zfill(10)
		IMSI = '7240{}{}'.format(random.randint(2,4), IMSI_Rand_Part)
		
		create_gtp_packet = IP(dst=IP_GGSN) / UDP(dport=2123) / gtp.GTPHeader() / gtp.GTPCreatePDPContextRequest()

		create_gtp_packet.IE_list = [

			gtp.IE_IMSI(imsi=IMSI),
			gtp.IE_Routing(MCC='724',MNC='02',LAC=53221, RAC=20),
			gtp.IE_SelectionMode(SelectionMode="MS"),
			gtp.IE_TEIDI(TEIDI=0),
			gtp.IE_TEICP(TEICI=fake_TEICI),
			gtp.IE_NSAPI(NSAPI=5),
			gtp.IE_ChargingCharacteristics(normal_charging=1),
			gtp.IE_EndUserAddress(PDPTypeNumber=0x8d),
			gtp.IE_AccessPointName(length=13, APN='timbrasil.br'),
			gtp.IE_GSNAddress(address='189.40.127.11'),
			gtp.IE_GSNAddress(address='189.40.127.10'),
			gtp.IE_MSInternationalNumber(length=8, digits='55{}{}'.format(random.randint(11,97), random.randint(900000000,999999999))),
			gtp.IE_QoS(length=15, allocation_retention_prioiry=2),
			gtp.IE_CommonFlags(length=1, dual_addr_bearer_fl=1),
			gtp.IE_RATType(RAT_Type=1),
			gtp.IE_UserLocationInformation(length=8, SAC=0x3ead, LAC=0xcfe5, MCC='724', MNC='02'),
			gtp.IE_EvolvedAllocationRetentionPriority(length=1, PL=0x06)
		

		]
	
        	a = sr1(create_gtp_packet,timeout=5,verbose=False)
		create_gtp_response = a[1]
		result = validate_response(create_gtp_response)

		for IE in create_gtp_response.IE_list:
			if IE.ietype == 17:
				response_TEIDI = IE.TEICI

		if result == "Success":
		
			delete_gtp_packet = IP(dst=IP_GGSN) / UDP(dport=2123) / gtp.GTPHeader(teid=response_TEIDI) / gtp.GTPDeletePDPContextRequest()
			delete_gtp_packet.IE_list = [gtp.IE_Teardown(),
                        	             gtp.IE_NSAPI(NSAPI=5)
                                	    ]

			b = sr1(delete_gtp_packet, timeout=5,verbose=False)
	
			print('GGSN {} is OK').format(ggsn.get(IP_GGSN))
		else:
			print("Create PDP Context Request Failed - {} is Faulty.").format(ggsn.get(IP_GGSN))


def validate_response(packet):
	for IE in packet.IE_list:
		if IE.ietype == 1:
			cause = IE.CauseValue
	# Convert CauseValue from Decimal to Bit --> Check the first two Bits --> If first two Bits == '10' it means Success
	# 3GPP TS29.060 Rel10

	if "{0:b}".format(int(cause))[0:2] == "10":
		return "Success"
	else:
		return "Failure"
				


if __name__ == "__main__":
	if args.loop and args.GGSN:
		main(args.loop, args.GGSN)
	elif args.loop:
		main(loop=args.loop)
	elif args.GGSN:
		main(GGSN=args.GGSN)
	else:
		main()
