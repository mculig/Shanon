--Functions for IPv4

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local IPv4={}

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
IPv4.relativeStackPosition = 1

IPv4.versionIhl = Field.new("ip.version") -- Version and IHL
IPv4.dscpEcn = Field.new("ip.dsfield") -- DSCP and ECN fields
IPv4.totalLength = Field.new("ip.len") -- Total length
IPv4.id = Field.new("ip.id") -- Identification field
IPv4.flags = Field.new("ip.flags") -- Flags and Fragment Offset
IPv4.ttl = Field.new("ip.ttl") -- Time to Live
IPv4.protocol = Field.new("ip.proto") -- Upper layer protocol number
IPv4.checksum = Field.new("ip.checksum") -- Checksum
IPv4.src = Field.new("ip.src") -- Source Address
IPv4.dst = Field.new("ip.dst") -- Destination Address


function IPv4.anonymize(tvb, protocolList, anonymizationPolicy)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = IPv4.relativeStackPosition
    IPv4.relativeStackPosition = IPv4.relativeStackPosition - 1

    --Get fields
    local ipVersionIhl = shanonHelpers.getRaw(tvb, IPv4.versionIhl, relativeStackPosition)
    local ipDscpEcn = shanonHelpers.getRaw(tvb, IPv4.dscpEcn, relativeStackPosition)
    local ipLengh = shanonHelpers.getRaw(tvb, IPv4.totalLength, relativeStackPosition)
    local ipId = shanonHelpers.getRaw(tvb, IPv4.id, relativeStackPosition)
    local ipFlags = shanonHelpers.getRaw(tvb, IPv4.flags, relativeStackPosition)
    local ipTtl = shanonHelpers.getRaw(tvb, IPv4.ttl,relativeStackPosition)
    local ipProcotol = shanonHelpers.getRaw(tvb, IPv4.protocol, relativeStackPosition)
    local ipChecksum = shanonHelpers.getRaw(tvb, IPv4.checksum, relativeStackPosition)
    local ipSrc = shanonHelpers.getRaw(tvb, IPv4.src, relativeStackPosition)
    local ipDst = shanonHelpers.getRaw(tvb, IPv4.dst, relativeStackPosition)

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local ipVersionIhlAnon
    local ipDscpEcnAnon
    local ipLengthAnon
    local ipIdAnon
    local ipFlagsAnon
    local ipTtlAnon
    local ipProtocolAnon
    local ipChecksumAnon 
    local ipSrcAnon
    local ipDstAnon

    --Anonymize stuff here
    ipVersionIhlAnon = ipVersionIhl
    ipDscpEcnAnon = ipDscpEcn
    ipLengthAnon = ipLengh
    ipIdAnon = ipId
    ipFlagsAnon = ipFlags
    ipTtlAnon = ipTtl
    ipProtocolAnon = ipProcotol
    ipChecksumAnon = ipChecksum
    ipSrcAnon = ipSrc
    ipDstAnon = ipDst

    --Write to the anonymized frame here
    return ipVersionIhlAnon .. ipDscpEcnAnon .. ipLengthAnon .. ipIdAnon .. ipFlagsAnon .. 
    ipTtlAnon .. ipProtocolAnon .. ipChecksumAnon .. ipSrcAnon .. ipDstAnon

end

--Return the module table
return IPv4