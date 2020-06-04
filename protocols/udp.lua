--Functions for UDP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local UDP={}

UDP.srcport = Field.new("udp.srcport")
UDP.dstport = Field.new("udp.dstport")
UDP.length = Field.new("udp.length")
UDP.checksum = Field.new("udp.checksum")

function UDP.anonymize(tvb, protocolList, anonymizationPolicy)
    --Get fields
    local udpSrc = shanonHelpers.getRaw(tvb, UDP.srcport())
    local udpDst = shanonHelpers.getRaw(tvb, UDP.dstport())
    local udpLength = shanonHelpers.getRaw(tvb, UDP.length())
    local udpChecksum = shanonHelpers.getRaw(tvb, UDP.checksum())

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