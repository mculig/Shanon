--Required. Create Config variable. Can be named anything
local Config = {}

--Anonymization output file name including extension. Regardless what is written here the file will always be a pcapng file.
--If this is omitted a default output file name will be used
Config.outputFile = "shanon_output.pcapng"

--The key file to use for the CryptoPAN algorithm
Config.cryptoPANKeyFile = "shanon_cryptoPAN.key"

--The anonymization policy. This policy is made up of anonymization rules for the individual protocols Shanon supports
--If a protocol is omitted a default policy will be used for that protocol
Config.anonymizationPolicy = {}

--The anonymization policy for the frame as written in the pcapng filesystem
--This policy only specifies how Shanon should deal with the timestamps of captured frames
Config.anonymizationPolicy.frame = {
    --Options: 
    --Absolute: The absolute time when the packet was captured. 
    --Relative: The relative time when the packet was captured compared to the start of the capture
    timestamp = "Relative"
}

--The anonymization policy for Ethernet
--The address anonymization method used here is also used to anonymize MAC addresses in ARP
Config.anonymizationPolicy.ethernet = {
    --Frame check sequence
    --Options:
    --Skip: Do not include a FCS with the captured frame
    --Recalculate: Calculate a new, correct FCS
    fcs = "Skip",
    --MAC addresses
    --Options:
    --Keep: Addresses are left unchanged
    --BlackMarker: Use a BlackMarker. The syntax is as follows: BlackMarker_Direction_CountBits. 
    --Example: BlackMarker_MSB_24 would apply the method to the most significant 24 bits
    --BlackMarker_LSB_24 would apply the method to the least significant 24 bits
    address = "BlackMarker_MSB_24",
    --Payload length
    --Options:
    --Recalculate: Calculate a new, correct length, based on the anonymized payload
    --Keep: Keep the original length
    length = "Recalculate"
}

--There is no entry for ARP since ARP relies on the IPv4 and Ethernet policies for anonymization

--The anonymization policy for IPv4
--The address anonymization method used here is also used to anonymize IPv4 addresses in ARP and ICMP Redirect Gateway Addresses
Config.anonymizationPolicy.ipv4 = {
    --Different anonymization rules can be specified for different subnets
    --These are optional, but if they exist they will be validated
    --Any option missing here will be taken from the default specified below
    --These options will be applied if the source or destination address is in the subnet
    subnets = {       
        ["192.168.1.0/24"] = {
            ttl = "SetValue_12"
        }
    },
    --The default rule is applied to each packet that doesn't match a particular subnet
    --Any option not specified in a subnet's anonymization policy will be taken from this default
    --Any option not in this default will be taken from a hardcoded default policy
    default = {
        --The DSCP field
        --Options:
        --Keep: Keep the field as is
        --Zero: Set this field to zeroes
        dscp = "Zero",
        --The ECN field
        --Options:
        --Keep: Keep the field as is
        --Zero: Set this field to zeroes
        ecn = "Zero",
        --The IPv4 ID field
        --Options:
        --Keep: Keep the field as is
        --BlackMarker: See the BlackMarker syntax example in the ethernet policy
        id = "BlackMarker_MSB_16",
        --The IPv4 Reserved, Flags and Fragment Offset fields
        --These are all treated as one field. 1 bit is reserved, 2 are flags (Don't fragment and More Fragments), 13 bits are the Fragment Offset
        --Options:
        --Keep: Keep the field as is
        --BlackMarker: See the BlackMarker syntax example in the ethernet policy 
        flagsAndOffset = "BlackMarker_MSB_16",
        --The TTL field
        --Options:
        --Keep: Keep TTL as it was
        --SetValue_N: Set the TTL field value to a specific number N. The range for this field is between 1 and 255 includive
        ttl = "SetValue_64",
        --The IPv4 Checksum
        --Options:
        --Keep: Keep the field as is
        --Recalculate: Calculate a new, valid checksum
        checksum = "Recalculate",
        --IPv4 Addresses
        --Different anonymization rules can be specified for different subnets.
        --Multiple rules can be specified as part of a table of rules and will be applied in the order of appearance
        --The default is applied to any address not part of a defined subnet
        --Options:
        --Keep: Keep the IPv4 address unchanged
        --BlackMarker: See the BlackMarker syntax example in the ethernet policy
        --CryptoPAN: Use the CryptoPAN algorithm to anonymize IPv4 addresses
        address = {
            ["192.168.1.0/24"] = {"Keep"},
            default = {"CryptoPAN"}
        }
    }
}

--The anonymization policy for ICMP
--ICMP Redirect Gateway Addresses are anonymized using the IPv4 anonymization policy rules
Config.anonymizationPolicy.icmp = {
    --The ICMP Checksum
    --Options:
    --Keep: Keep the field as is
    --Recalculate: Calculate a new, valid checksum
    checksum = "Recalculate",
    --ICMP Echo and Timestamp identifiers and sequence numbers
    --Options:
    --Keep: Keep the field as is 
    --Zero: Set the field to zero
    id = "Zero",
    sequenceNumber = "Zero",
    --Parameter Problem Pointer
    --Options:
    --Keep: Keep the pointer unchanged
    --Zero: Set the pointer to zero
    ppPointer = "Zero",
    --ICMP Timestamp Timestamps
    --Options:
    --Keep: Keep the fields as they are
    --BlackMarker: See the BlackMarker syntax example in the ethernet policy
    timestamp = "BlackMarker_MSB_24"
}

--The anonymization policy for IPv6
Config.anonymizationPolicy.ipv6 = {
    --Different anonymization rules can be specified for different subnets
    --These behave the same way rules for IPv4 subnets behave
    subnets = {
        ["fe80::/10"] = {
            trafficClass = "Zero"
        }
    },
    --The default rule is applied to each packet that doesn't match a particular subnet
    --This is the same as with IPv4
    default = {
        --Traffic class
        --Options:
        --Keep: Keep the field as is
        --Zero: Set the field to all zeroes
        trafficClass = "Zero",
        --Flow Label
        --Options:
        --Keep: Keep the field as is
        --Zero: Set the field to all zeroes
        flowLabel = "Zero",
        --IPv6 Hop Limit (TTL)
        --Options:
        --Keep: Keep value as is
        --SetValue_N: Set the TTL field to a specific number N. The range for this field is between 1 and 255 includive
        hopLimit = "SetValue_64",
        --Hop by hop extension headers
        --Whether to keep or discard this option
        --Options: True/False
        headers_hopByHop_keep = "True",
        --Option payload
        --Options:
        --Zero: Set the payload to all zeroes, but preserve length
        --Minimum: Set the payload to a minimum-length payload
        --Keep: Keep the payload as it was, length is preserved
        headers_hopByHop_payload = "Zero",
        --Routing extension headers
        --Same options as hop by hop
        headers_routing_keep = "True",
        headers_routing_payload = "Zero",
        --Fragmentation headers
        --Fragment offset
        --Options:
        --Keep: Keep the fragment offset unchanged
        --Zero: Set this field to zero
        headers_fragment_fragmentOffset = "Zero",
        --Identification field
        --Options:
        --Keep: Keep the identification field unchanged
        --Zero: Set this field to zero
        headers_fragment_identification = "Zero",
        --Destination Options headers
        --Same options as hop by hop
        headers_dstOpt_keep = "True",
        headers_dstOpt_payload = "Zero",
        --IPv6 Addresses
        --The rules can be specified in the same way as for IPv4 addresses. See the IPv4 policy for details
        --IPv6 validation is complex and as such some invalid addresses can still make it through. Please take extra care that subnets are properly defined
        address = {
            ["fe80::/10"] = {"Keep"},
            default = {"CryptoPAN"}
        }
    }

}

--The anonymization policy for ICMPv6
Config.anonymizationPolicy.icmpv6 = {
    --The ICMPv6 Checksum
    --Options:
    --Keep: Keep the field as is
    --Recalculate: Calculate a new, valid checksum
    checksum = "Recalculate",
    --ICMPv6 Echo identifiers and sequence numbers
    --Options:
    --Keep: Keep the field as is 
    --Zero: Set the field to zero
    echoId = "Zero",
    echoSequenceNumber = "Zero",
    --Parameter Problem Pointer
    --Options:
    --Keep: Keep the pointer unchanged
    --Zero: Set the pointer to zero
    ppPointer = "Zero",
    --Packet Too Big MTU value
    --Options:
    --Keep: Keep the value intact
    --Zero: Set the value to zero
    --SetValue_N: Set the MTU field to a specific number N. The range for this field is between 1280 and 200000 inclusive
    ptbMtu = "SetValue_1337"

}

--The anonymization policy for NDP
--This policy is validated together with ICMPv6 since the anonymization of NDP is done by the ICMPv6 anonymizer
Config.anonymizationPolicy.ndp = {
    --Router Advertisement
    --Hop Limit
    --Options:
    --Keep: Keep the Hop Limit field as is
    --SetValue_N: Set the Hop Limit field to a specific number N. The range for this field is between 1 and 255 inclusive
    raHopLimit = "SetValue_64",
    --Router Advertisement Managed Address Configuration and Other Configuration flags
    --Options:
    --Keep: Keep the value of the flag
    --Zero: Set the flag to 0
    raManagedFlag = "Zero",
    raOtherFlag = "Zero",
    --Router Advertisement Lifetimes. Lifetime is in seconds, Reachable and Retransmit time in miliseconds.
    --Options:
    --Keep: Keep the value as it is
    --SetValue_N: Set the value of the times to specific values
    --Zero: Set the values of the times to zero
    raLifetime = "SetValue_3600", --The range for this field is between 0 and 9000 inclusive
    raReachableTime = "SetValue_3600000", --The range for this field is between 0 and 3600000 inclusive
    raRetransTime = "SetValue_3600000", --The range for this field is between 0 and 3600000 inclusive
    --Neighbour Advertisement
    --Neighbour Advertisement Router and Override flags
    --Options:
    --Keep: Keep the flag intact
    --Zero: Set the flag to zero
    naRouterFlag = "Keep",
    naOverrideFlag = "Keep",
    --Prefix Information Option
    --The subnet prefix length of the Prefix Option
    --Options:
    --Keep: Keep the prefix intact
    --SetValue_N: Set the value of the prefix to a specific value. This value ranges from 0 to 128 inclusive
    optPrefixPrefixLength = "Keep", 
    --The On-link and Autoconfiguation flags
    --Options:
    --Keep: Keep the flags as they are
    --Zero: Set the flags to zero
    optPrefixOnLinkFlag = "Keep",
    optPrefixSLAACFlag = "Keep",
    --The valid and preferred lifetime of the prefixes in seconds
    --Options:
    --Keep: Keep the values as they are
    --SetValue_N: Set the value of the times to specific values. The range for this field is between 100 and 259200
    --Infinity: Set the values to infinity
    optPrefixValidLifetime = "Infinity", 
    optPrefixPreferredLifetime = "Infinity",
    --MTU Option
    --Options:
    --Keep: Keep the value intact
    --Zero: Set the value to zero
    --SetValue_N: Set the MTU field to a specific number N. The range for this field is between 1280 and 200000
    optMtuMtu = "SetValue_1500" 
}

--The anonymization policy for UDP
Config.anonymizationPolicy.udp = {
    --UDP Source and Destination Ports
    --Options:
    --Keep: Keep the original source port
    --KeepRange: Keep the original source port range, but not the specific pot number
    --Zero: Set the port to zero
    sourcePort = "KeepRange",
    destinationPort = "KeepRange",
    --UDP payload length
    --Options: 
    --Keep: Keep value as is
    --Recalculate: Calculate new length
    length = "Keep",
    --UDP Checksum
    --Options:
    --Keep: Keep checksum as is
    --Zero: Set the checksum to zero (UDP checksums are optional)
    --Recalculate: Calculate a new UDP checksum
    checksum = "Recalculate",
    --UDP payload
    --Options: 
    --KeepOriginal: Keep the original payload. Discards any payload provided by any higher-layer anonymizer and keeps the UDP payload as it originally was
    --KeepAnonymized: Keep the anonymized payload if present, if not provide a minimum payload (length="Recalculate") or generate a zero payload (lenght="Keep")
    --Discard: Discards the payload completely, regardless of higher-layer anonymizers, and provides a generated zero payload the length of which depends on
    --the length option. If the original length needs to be preserved an appropriate-length payload will be generaed
    payload = "Discard"
}

--The anonymization policy for TCP
--TODO: WIP
Config.anonymizationPolicy.tcp = {
    --TCP Source and Destination Ports
    --The options are the same as for UDP
    sourcePort = "KeepRange",
    destinationPort = "KeepRange",
    --TCP Urgent Flag.
    --Options:
    --Keep: Keep this flag
    --Zero: Set this flag to zero
    flagUrgent = "Zero",
    --TCP Checksum
    --Options:
    --Keep: Keep checksum as is
    --Recalculate: Calculate a new UDP checksum
    checksum = "Recalculate",    
    --TCP Urgent Pointer
    --Options:
    --Keep: Keep the Urgent Pointer value if it was set
    --Zero: Set the Urgent Pointer to zero
    urgentPointer = "Zero",
    --TCP Timestamp Option
    --Options:
    --Discard: Discard timestamp options if present
    --Keep: Keep the timestamp as is
    --BlackMarker: See the BlackMarker syntax example in the ethernet policy 
    optTimestamp = "BlackMarker_MSB_16"
}


--Required. Return the variable created at the start. This must be the last line
return Config