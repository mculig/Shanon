--Functions for IPv6

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local IPv6={}

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
IPv6.relativeStackPosition = 1

IPv6.version_class_label = Field.new("ipv6.flow") -- Version, Traffic Class and Flow label
IPv6.payload_length = Field.new("ipv6.plen") -- Payload length
IPv6.next_header = Field.new("ipv6.nxt") -- Next Header
IPv6.hop_limit = Field.new("ipv6.hlim") -- Hop Limit
IPv6.src = Field.new("ipv6.src") -- Source Address
IPv6.dst = Field.new("ipv6.dst") -- Destination Address
--TODO: Need to add options

function IPv6.anonymize(tvb, protocolList, anonymizationPolicy)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = IPv6.relativeStackPosition
    IPv6.relativeStackPosition = IPv6.relativeStackPosition - 1

    --Get fields
    local versionClassLabel= shanonHelpers.getRaw(tvb, IPv6.version_class_label, relativeStackPosition)
    local payloadLength = shanonHelpers.getRaw(tvb, IPv6.payload_length, relativeStackPosition)
    local nextHeader = shanonHelpers.getRaw(tvb, IPv6.next_header, relativeStackPosition)
    local hopLimit = shanonHelpers.getRaw(tvb, IPv6.hop_limit, relativeStackPosition)
    local src = shanonHelpers.getRaw(tvb, IPv6.src, relativeStackPosition)
    local dst = shanonHelpers.getRaw(tvb, IPv6.dst, relativeStackPosition)

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local versionClassLabelAnon
    local payloadLengthAnon
    local nextHeaderAnon
    local hopLimitAnon
    local srcAnon
    local dstAnon

    --Anonymize stuff here
    versionClassLabelAnon = versionClassLabel
    payloadLengthAnon = payloadLength
    nextHeaderAnon = nextHeader
    hopLimitAnon = hopLimit
    srcAnon = src
    dstAnon = dst

    --Return the anonymization result
    return versionClassLabelAnon .. payloadLengthAnon .. nextHeaderAnon .. hopLimitAnon .. srcAnon .. dstAnon
end

--Return the module table
return IPv6