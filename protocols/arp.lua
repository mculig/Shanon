--Functions for ARP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"
local ethernet = require "protocols.ethernet"
local ipv4 = require "protocols.ipv4"

--Module table
local ARP={}

--The filter name is used when looking for instances of this protocol
ARP.filterName = "arp"


--Relative stack position is used to determine which of many possible instances of this protocol is being processed
ARP.relativeStackPosition = 1

--Fields
ARP.hwAddrSpace = Field.new("arp.hw.type")
ARP.protoAddrSpace = Field.new("arp.proto.type")
ARP.hwAddrLength = Field.new("arp.hw.size")
ARP.protoAddrLength = Field.new("arp.proto.size")
ARP.opcode = Field.new("arp.opcode")
ARP.hwAddrSrc = Field.new("arp.src.hw_mac")
ARP.protoAddrSrc = Field.new("arp.src.proto_ipv4")
ARP.hwAddrDst = Field.new("arp.dst.hw_mac")
ARP.protoAddrDst = Field.new("arp.dst.proto_ipv4")

--Is the anonymization policy valid
ARP.policyIsValid = false

function ARP.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

    --Validate the policy
    --ARP uses the same policies as Ethernet and IPv4 so we just import the Ethernet policy and validate it
    --This assumes we're using ARP with Ethernet and IPv4
    if ARP.policyIsValid == false then 
        ethernet.validatePolicy(config)
        ipv4.validatePolicy(config)
        ARP.policyIsValid = true
    end

    policy = {}
    policy.eth = config.anonymizationPolicy.ethernet
    policy.ipv4 = config.anonymizationPolicy.ipv4

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = ARP.relativeStackPosition
    ARP.relativeStackPosition = ARP.relativeStackPosition - 1

    --Get fields
    local arpHwAddrSpace = shanonHelpers.getRaw(tvb, ARP.hwAddrSpace, relativeStackPosition)
    local arpProtoAddrSpace = shanonHelpers.getRaw(tvb, ARP.protoAddrSpace, relativeStackPosition)
    local arpHwAddrLength = shanonHelpers.getRaw(tvb, ARP.hwAddrLength, relativeStackPosition)
    local arpProtoAddrLength = shanonHelpers.getRaw(tvb, ARP.protoAddrLength, relativeStackPosition)
    local arpOpcode = shanonHelpers.getRaw(tvb, ARP.opcode, relativeStackPosition)
    local arpHwAddrSrc = shanonHelpers.getRaw(tvb, ARP.hwAddrSrc, relativeStackPosition)
    local arpProtoAddrSrc = shanonHelpers.getRaw(tvb, ARP.protoAddrSrc, relativeStackPosition)
    local arpHwAddrDst = shanonHelpers.getRaw(tvb, ARP.hwAddrDst, relativeStackPosition)
    local arpProtoAddrDst = shanonHelpers.getRaw(tvb, ARP.protoAddrDst, relativeStackPosition)

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local arpHwAddrSpaceAnon
    local arpProtoAddrSpaceAnon
    local arpHwAddrLengthAnon
    local arpProtoAddrLengthAnon
    local arpOpcodeAnon
    local arpHwAddrSrcAnon
    local arpProtoAddrSrcAnon
    local arpHwAddrDstAnon
    local arpProtoAddrDstAnon

    --Anonymize stuff here 
    
    --These fields all remain unchanged
    arpHwAddrSpaceAnon = arpHwAddrSpace
    arpProtoAddrSpaceAnon = arpProtoAddrSpace
    arpHwAddrLengthAnon = arpHwAddrLength
    arpProtoAddrLengthAnon = arpProtoAddrLength
    arpOpcodeAnon = arpOpcode

    --For hardware addresses the same anonymization scheme as for Ethernet is used
    if policy.eth.address == "Keep" then 
        arpHwAddrSrcAnon = arpHwAddrSrc
        arpHwAddrDstAnon = arpHwAddrDst
    else 
        local blackMarkerDirection, blackMarkerLength = shanonHelpers.getBlackMarkerValues(policy.eth.address)
        arpHwAddrSrcAnon = libAnonLua.black_marker(arpHwAddrSrc, blackMarkerLength, blackMarkerDirection)
        arpHwAddrDstAnon = libAnonLua.black_marker(arpHwAddrDst, blackMarkerLength, blackMarkerDirection)
    end

    --For protocol addresses the same anonymization scheme as for IPv4 is used
    local addressPolicy
    --If we have per-subnet policies
    if policy.ipv4.subnets ~= nil then
        for subnet, subnetPolicy in pairs(policy.ipv4.subnets) do
            if libAnonLua.ip_in_subnet(arpProtoAddrSrc, subnet) or libAnonLua.ip_in_subnet(arpProtoAddrDst, subnet) then 
                addressPolicy = subnetPolicy
                break
            end
        end
    end
    --If we don't have a matching subnet, use the default
    if addressPolicy == nil then
        addressPolicy = policy.ipv4.default
    end

    --Used to check if source and destination were anonymized
    local srcAnonymized = false
    local dstAnonymized = false

    --Check if our addresses match any of the specified subnets and anonymize accordingly
    for subnet, anonymizationMethods in pairs(addressPolicy.address) do
        if subnet == "default" then 
            --Skip default here. If neither address is in any of the subnets then we'll default later
        else
            --Check if src is in the subnet
            if srcAnonymized == false and libAnonLua.ip_in_subnet(arpProtoAddrSrc, subnet) then 
                arpProtoAddrSrcAnon= ipv4.applyAnonymizationMethods(arpProtoAddrSrc, anonymizationMethods)
                srcAnonymized = true
            end
            --Check if dst is in the subnet
            if dstAnonymized == false and libAnonLua.ip_in_subnet(arpProtoAddrDst, subnet) then
                arpProtoAddrDstAnon = ipv4.applyAnonymizationMethods(arpProtoAddrDst, anonymizationMethods)
                dstAnonymized = true
            end
        end
        --End the loop if both have been anonymized
        if srcAnonymized and dstAnonymized then 
            break
        end
    end

    --If source or destination haven't been anonymized, apply the default
    if not srcAnonymized then
        arpProtoAddrSrcAnon = ipv4.applyAnonymizationMethods(arpProtoAddrSrc, addressPolicy.address.default)
    end

    if not dstAnonymized then 
        arpProtoAddrDstAnon = ipv4.applyAnonymizationMethods(arpProtoAddrDst, addressPolicy.address.default)
    end
    
    --Write to the anonymized frame here
    --Variable used for multi-line concat to improve readability
    local anonymizedARP = arpHwAddrSpaceAnon .. arpProtoAddrSpaceAnon .. arpHwAddrLengthAnon .. arpProtoAddrLengthAnon .. arpOpcodeAnon
    anonymizedARP = anonymizedARP .. arpHwAddrSrcAnon .. arpProtoAddrSrcAnon .. arpHwAddrDstAnon .. arpProtoAddrDstAnon 
    
    anonymizedFrame = anonymizedARP .. anonymizedFrame

    return anonymizedFrame
end

--Return the module table
return ARP     