--Functions for ARP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local ARP={}

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

function ARP.anonymize(tvb, protocolList, anonymizationPolicy)
    --Get fields
    local arpHwAddrSpace = shanonHelpers.getRaw(tvb, ARP.hwAddrSpace())
    local arpProtoAddrSpace = shanonHelpers.getRaw(tvb, ARP.protoAddrSpace())
    local arpHwAddrLength = shanonHelpers.getRaw(tvb, ARP.hwAddrLength())
    local arpProtoAddrLength = shanonHelpers.getRaw(tvb, ARP.protoAddrLength())
    local arpOpcode = shanonHelpers.getRaw(tvb, ARP.opcode())
    local arpHwAddrSrc = shanonHelpers.getRaw(tvb, ARP.hwAddrSrc())
    local arpProtoAddrSrc = shanonHelpers.getRaw(tvb, ARP.protoAddrSrc())
    local arpHwAddrDst = shanonHelpers.getRaw(tvb, ARP.hwAddrDst())
    local arpProtoAddrDst = shanonHelpers.getRaw(tvb, ARP.protoAddrDst())

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
    arpHwAddrSpaceAnon = arpHwAddrSpace
    arpProtoAddrSpaceAnon = arpProtoAddrSpace
    arpHwAddrLengthAnon = arpHwAddrLength
    arpProtoAddrLengthAnon = arpProtoAddrLength
    arpOpcodeAnon = arpOpcode
    arpHwAddrSrcAnon = arpHwAddrSrc
    arpProtoAddrSrcAnon = arpProtoAddrSrc
    arpHwAddrDstAnon = arpHwAddrDst
    arpProtoAddrDstAnon = arpProtoAddrDst


    --Write to the anonymized frame here
    --Variable used for multi-line concat to improve readability
    local anonymizedARP = arpHwAddrSpaceAnon .. arpProtoAddrSpaceAnon .. arpHwAddrLengthAnon .. arpProtoAddrLengthAnon .. arpOpcodeAnon
    anonymizedARP = anonymizedARP .. arpHwAddrSrcAnon .. arpProtoAddrSrcAnon .. arpHwAddrDstAnon .. arpProtoAddrDstAnon 
    return anonymizedARP
end

--Return the module table
return ARP     