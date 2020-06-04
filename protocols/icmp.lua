--Functions for ICMP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local ICMP={}

ICMP.type = Field.new("icmp.type")
ICMP.code = Field.new("icmp.code")
ICMP.checksum = Field.new("icmp.checksum")
--These two fields show up in Echo, Echo Reply, Timestamp and Timestamp Reply
ICMP.identifier = Field.new("icmp.ident")
ICMP.sequenceNumber = Field.new("icmp.seq")
--This shows up in redirect
ICMP.redirectGateway = Field.new("icmp.redir_gw")
--This shows up in Parameter Problem
ICMP.pointer = Field.new("icmp.pointer")
--These show up in Timestamp and Timestamp Reply
ICMP.originateTimestamp = Field.new("icmp.originate_timestamp")
ICMP.receiveTimestamp = Field.new("icmp.receive_timestamp")
ICMP.transmitTimestamp = Field.new("icmp.transmit_timestamp")

function ICMP.anonymize(tvb, protocolList, anonymizationPolicy)
    --Get fields
    local icmpType = shanonHelpers.getRaw(tvb, ICMP.type())
    local icmpCode = shanonHelpers.getRaw(tvb, ICMP.code())
    local icmpChecksum = shanonHelpers.getRaw(tvb, ICMP.checksum())

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local icmpTypeAnon
    local icmpCodeAnon
    local icmpChecksumAnon

    --Anonymize stuff here
    icmpTypeAnon = icmpType
    icmpCodeAnon = icmpCode
    icmpChecksumAnon = icmpChecksum

    --Add anonymized header fields to ICMP message
    local icmpMessage = icmpTypeAnon .. icmpCodeAnon .. icmpChecksumAnon

    --The rest is handled differently for different ICMP types
    local tmpType = ICMP.type().value
    if tmpType == 0 or tmpType == 8 then
        --Echo and Echo Reply
        --Get fields
        local icmpId = shanonHelpers.getRaw(tvb, ICMP.identifier())
        local icmpSeq = shanonHelpers.getRaw(tvb, ICMP.sequenceNumber())
        local icmpData = shanonHelpers.getRest(tvb, ICMP.sequenceNumber())

        --Anonymize fields 
        local icmpIdAnon = icmpId
        local icmpSeqAnon = icmpSeq
        local icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpIdAnon .. icmpSeqAnon .. icmpDataAnon

    elseif tmpType == 3 then
        --Destination unreachable
        --Get fields
        --4 unused bytes past the checksum are grabbed from the buffer.
        --This method is used instead of using Field.new("icmp.unused") because there may be used for the unused field
        --but these uses aren't covered by this version of Shanon
        local offset = ICMP.checksum().offset+ICMP.checksum().len
        local icmpUnused = tvb:range(offset, 4):bytes():raw()
        --Add 4 to offset to go past the unused bytes and capture just data
        local offset = offset + 4
        local icmpData = shanonHelpers.getRestFromOffset(tvb, offset)
        
        --Anonymize fields
        local icmpUnusedAnon = icmpUnused
        local icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpUnusedAnon .. icmpDataAnon

    elseif tmpType == 5 then
        --Redirect
        --Get field
        local icmpRedirectGateway = shanonHelpers.getRaw(tvb, ICMP.redirectGateway())
        local icmpData = shanonHelpers.getRest(tvb, ICMP.redirectGateway())

        --Anonymize fields
        local icmpRedirectGatewayAnon = icmpRedirectGateway
        local icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpRedirectGatewayAnon .. icmpDataAnon
    elseif tmpType == 12 then
        --Parameter problem 
        --Get fields
        local icmpPointer = shanonHelpers.getRaw(tvb, ICMP.pointer())
        -- 3 Unused bytes after the pointer. 
        local icmpUnused = tvb:range(ICMP.pointer().offset + 1, 3):bytes():raw()
        -- Data starts 4 bytes away from pointer offset. 
        local icmpData = shanonHelpers.getRestFromOffset(tvb, ICMP.pointer().offset + 4)

        --Anonymized fields
        local icmpPointerAnon
        local icmpUnusedAnon
        local icmpDataAnon 

        --Anonymize fields
        icmpPointerAnon = icmpPointer
        icmpUnusedAnon = icmpUnused
        icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpPointerAnon .. icmpUnusedAnon .. icmpDataAnon

    elseif tmpType == 13 or tmpType == 14 then
        --Timestamp and timestamp reply
        --Get fields
        local icmpIdentifier = shanonHelpers.getRaw(tvb, ICMP.identifier())
        local icmpSeq = shanonHelpers.getRaw(tvb, ICMP.sequenceNumber())
        local icmpOriginateTimestamp = shanonHelpers.getRaw(tvb, ICMP.originateTimestamp())
        local icmpReceiveTimestamp = shanonHelpers.getRaw(tvb, ICMP.receiveTimestamp())
        local icmpTransmitTimestamp = shanonHelpers.getRaw(tvb, ICMP.transmitTimestamp())

        --Anonymized fields
        local icmpIdentifierAnon
        local icmpSeqAnon
        local icmpOriginateTimestampAnon
        local icmpReceiveTimestampAnon
        local icmpTransmitTimestampAnon

        --Anonymize fields
        icmpIdentifierAnon = icmpIdentifier
        icmpSeqAnon = icmpSeq
        icmpOriginateTimestampAnon = icmpOriginateTimestamp
        icmpReceiveTimestampAnon = icmpReceiveTimestamp
        icmpTransmitTimestampAnon = icmpTransmitTimestamp

        --Add anonymized fields to icmp message
        icmpMessage = icmpMessage .. icmpIdentifierAnon .. icmpSeqAnon .. icmpOriginateTimestampAnon
        icmpMessage = icmpMessage .. icmpReceiveTimestampAnon .. icmpTransmitTimestampAnon
    else
        --Handle other messages
        --Get data
        local icmpData = shanonHelpers.getRest(tvb, ICMP.checksum())

        --Anonymized fields
        local icmpDataAnon

        --Anonymize fields
        icmpDataAnon = icmpData

        --Add anonymized fields to icmp message
        icmpMessage = icmpMessage .. icmpDataAnon
    end

    --Return the anonymization result
    return icmpMessage
end

--Return the module table
return ICMP