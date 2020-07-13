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
    fcs = "Recalculate",
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

--The anonymization policy for IPv4
--The address anonymization method used here is also used to anonymize IPv4 addresses in ARP
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
        --The DSCP and ECN fields share a single byte
        --Options:
        --Keep: Keep the field as is
        --BlackMarker: Apply a BlackMarker to the field
        dscpEcn = "BlackMarker_MSB_8",
        --The length of the payload
        --Options:
        --Keep: Keep the field as is
        --Recalculate: Calculate new length
        length = "Recalculate",
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
        --SetValue_N: Set the TTL field value to a specific number N
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
            default = {"BlackMarker_MSB_8", "CryptoPAN"}
        }
    }
}

--Required. Return the variable created at the start. This must be the last line
return Config