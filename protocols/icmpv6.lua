--Functions for ICMPv6

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local ICMPv6={}

ICMPv6.type = Field.new("icmpv6.type")
ICMPv6.code = Field.new("icmpv6.code")
ICMPv6.checksum = Field.new("icmpv6.checksum")
--These two fields only show up in Echo and Echo Reply
ICMPv6.identifier = Field.new("icmpv6.echo.identifier")
ICMPv6.sequenceNumber = Field.new("icmpv6.echo.sequence_number")
--This shows up in Parameter Problem
ICMPv6.pointer = Field.new("icmpv6.pointer")
--This shows up in Packet Too Big
ICMPv6.mtu = Field.new("icmpv6.mtu")

--NDP
ICMPv6.NDP={}
--These show up in NDP Router Advertisement
ICMPv6.NDP.RA={}
ICMPv6.NDP.RA.hopLimit = Field.new("icmpv6.nd.ra.cur_hop_limit")
ICMPv6.NDP.RA.routerLifetime = Field.new("icmpv6.nd.ra.router_lifetime")
ICMPv6.NDP.RA.reachableTime = Field.new("icmpv6.nd.ra.reachable_time")
ICMPv6.NDP.RA.retransTime = Field.new("icmpv6.nd.ra.retrans_timer")
--Options
ICMPv6.NDP.RA.OPT={}
ICMPv6.NDP.RA.OPT.

function ICMPv6.anonymize(tvb, protocolList, anonymizationPolicy)

--Get fields
local icmpType = shanonHelpers.getRaw(tvb, ICMPv6.type())
local icmpCode = shanonHelpers.getRaw(tvb, ICMPv6.code())
local icmpChecksum = shanonHelpers.getRaw(tvb, ICMPv6.checksum())

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
local tmpType = ICMPv6.type().value
    if tmpType == 128 or tmpType == 129 then
        --Echo and Echo Reply
        --Get fields
        local icmpId = shanonHelpers.getRaw(tvb, ICMPv6.identifier())
        local icmpSeq = shanonHelpers.getRaw(tvb, ICMPv6.sequenceNumber())
        local icmpData = shanonHelpers.getRest(tvb, ICMPv6.sequenceNumber())

        --Anonymize fields 
        local icmpIdAnon = icmpId
        local icmpSeqAnon = icmpSeq
        local icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpIdAnon .. icmpSeqAnon .. icmpDataAnon

    elseif tmpType == 1 then
        --Destination unreachable
        --Get fields
        --4 unused bytes past the checksum are grabbed from the buffer.
        --This method is used instead of using Field.new("icmp.unused") because there may be used for the unused field
        --but these uses aren't covered by this version of Shanon
        local offset = ICMPv6.checksum().offset+ICMPv6.checksum().len
        local icmpUnused = tvb:range(offset, 4):bytes():raw()
        --Add 4 to offset to go past the unused bytes and capture just data
        local offset = offset + 4
        local icmpData = shanonHelpers.getRestFromOffset(tvb, offset)
        
        --Anonymize fields
        local icmpUnusedAnon = icmpUnused
        local icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpUnusedAnon .. icmpDataAnon

    elseif tmpType == 4 then
        --Parameter problem 
        --Get fields
        local icmpPointer = shanonHelpers.getRaw(tvb, ICMPv6.pointer())
        -- Data
        local icmpData = shanonHelpers.getRestFromOffset(tvb, ICMPv6.pointer().offset+ICMPv6.pointer().len)

        --Anonymized fields
        local icmpPointerAnon
        local icmpDataAnon 

        --Anonymize fields
        icmpPointerAnon = icmpPointer
        icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpPointerAnon .. icmpDataAnon

    elseif tmpType == 2 then
        --Packet Too Big
        --Get fields
        local icmpMTU = shanonHelpers.getRaw(tvb, ICMPv6.mtu())
        local icmpData = shanonHelpers.getRest(tvb, ICMPv6.mtu())

        --Anonymized fields
        local icmpMTUAnon
        local icmpDataAnon

        --Anonymize fields
        icmpMTUAnon = icmpMTU
        icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpMTUAnon .. icmpDataAnon
    elseif tmpType == 134 then
        --NDP router advertisement

    else
        --Handle other messages
        --Get data
        local icmpData = shanonHelpers.getRest(tvb, ICMPv6.checksum())

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
return ICMPv6