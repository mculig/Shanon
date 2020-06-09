--Functions for UDP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local UDP={}

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
UDP.relativeStackPosition = 1

UDP.srcport = Field.new("udp.srcport")
UDP.dstport = Field.new("udp.dstport")
UDP.length = Field.new("udp.length")
UDP.checksum = Field.new("udp.checksum")

function UDP.anonymize(tvb, protocolList, anonymizationPolicy)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = UDP.relativeStackPosition
    UDP.relativeStackPosition = UDP.relativeStackPosition - 1

    --Get fields
    local udpSrc = shanonHelpers.getRaw(tvb, UDP.srcport, relativeStackPosition)
    local udpDst = shanonHelpers.getRaw(tvb, UDP.dstport, relativeStackPosition)
    local udpLength = shanonHelpers.getRaw(tvb, UDP.length, relativeStackPosition)
    local udpChecksum = shanonHelpers.getRaw(tvb, UDP.checksum, relativeStackPosition)

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local udpSrcAnon
    local udpDstAnon
    local udpLengthAnon
    local udpChecksumAnon

    --Anonymize stuff here
    udpSrcAnon = udpSrc
    udpDstAnon = udpDst
    udpLengthAnon = udpLength
    udpChecksumAnon = udpChecksum

    --Write to the anonymized frame here
    return udpSrcAnon .. udpDstAnon .. udpLengthAnon .. udpChecksumAnon
end

--Return the module table
return UDP