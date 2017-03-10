from scapy.all import *
from scapy.contrib import gtp

def main():


        IP_GGSN = '10.221.58.214'
        ggsn = {'10.221.48.252': 'GPHPT01',
		        '10.221.58.214': 'GPHPT02'}

	    fake_TEICI = 0xFFFFF
	    create_gtp_packet = IP(dst=IP_GGSN) / UDP(dport=2123) / gtp.GTPHeader() / gtp.GTPCreatePDPContextRequest()

	    create_gtp_packet.IE_list = [

                                gtp.IE_IMSI(imsi='724279999999999'),
                                gtp.IE_Routing(MCC='724',MNC='27',LAC=53229, RAC=20),
                                gtp.IE_SelectionMode(SelectionMode="MS"),
                                gtp.IE_TEIDI(TEIDI=0),
                                gtp.IE_TEICP(TEICI=fake_TEICI),
                                gtp.IE_NSAPI(NSAPI=5),
                                gtp.IE_ChargingCharacteristics(normal_charging=1),
                                gtp.IE_EndUserAddress(PDPTypeNumber=0x8d),
                                gtp.IE_AccessPointName(length=8, APN='internet'),
                                gtp.IE_GSNAddress(address='10.40.127.11'),
                                gtp.IE_GSNAddress(address='10.40.127.10'),
                                gtp.IE_MSInternationalNumber(length=8, digits='5521999999999'),
                                gtp.IE_QoS(length=15, allocation_retention_prioiry=2),
                                gtp.IE_CommonFlags(length=1, dual_addr_bearer_fl=1),
                                gtp.IE_RATType(RAT_Type=1),
                                gtp.IE_UserLocationInformation(length=8, SAC=0x3ead, LAC=0xcfed, MCC='724', MNC='27'),
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
	main()
