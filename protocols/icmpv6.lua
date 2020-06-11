--Functions for ICMPv6

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local ICMPv6={}

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
ICMPv6.relativeStackPosition = 1


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
ICMPv6.OPT={}
ICMPv6.OPT.type = Field.new("icmpv6.opt.type")
ICMPv6.OPT.length = Field.new("icmpv6.opt.length")
--Prefix information
ICMPv6.OPT.Prefix = {}
--Since multiple same options can in theory exist, we need to apply a count
ICMPv6.OPT.Prefix.Count = 1
ICMPv6.OPT.Prefix.PrefixLength = Field.new("icmpv6.opt.prefix.length")
--1 Byte flags will be extracted from TVB directly
ICMPv6.OPT.Prefix.ValidLifetime = Field.new("icmpv6.opt.prefix.valid_lifetime")
ICMPv6.OPT.Prefix.PreferredLifetime = Field.new("icmpv6.opt.prefix.preferred_lifetime")
--4 Bytes of reserved space will be extracted from TVB directly
ICMPv6.OPT.Prefix.Prefix = Field.new("icmpv6.opt.prefix")
--Source/Target Link-layer Address
ICMPv6.OPT.LinkAddress = {}
--Since multiple same options can in theory exist, we need to apply a count
ICMPv6.OPT.LinkAddress.Count = 1
ICMPv6.OPT.LinkAddress.LinkAddress = Field.new("icmpv6.opt.linkaddr")
--MTU
ICMPv6.OPT.MTU = {}
--Since multiple same options can in theory exist, we need to apply a count
ICMPv6.OPT.MTU.Count = 1
--There are 2 bytes of reserved data that need to be fetched before this field
ICMPv6.OPT.MTU.MTU = Field.new("icmpv6.opt.mtu")
--Redirect
ICMPv6.OPT.Redirect = {}
--Since multiple same options can in theory exist, we need to apply a count
ICMPv6.OPT.Redirect.Count = 1 --Can't imagine having 2 of these options in one NDP message, but support it still
--Redirected packet
--6 bytes are reserved and are fetched before this field
ICMPv6.OPT.Redirect.RedirectedPacket = Field.new("icmpv6.opt.redirected_packet")


function ICMPv6.anonymize(tvb, protocolList, anonymizationPolicy)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = ICMPv6.relativeStackPosition
    ICMPv6.relativeStackPosition = ICMPv6.relativeStackPosition - 1
    
    --Get fields
    local icmpType = shanonHelpers.getRaw(tvb, ICMPv6.type, relativeStackPosition)
    local icmpCode = shanonHelpers.getRaw(tvb, ICMPv6.code, relativeStackPosition)
    local icmpChecksum = shanonHelpers.getRaw(tvb, ICMPv6.checksum, relativeStackPosition)

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
    local tmp = { ICMPv6.type() }
    local tmpType = tmp[relativeStackPosition].value
    if tmpType == 128 or tmpType == 129 then
        --Echo and Echo Reply
        --Get fields
        local icmpId = shanonHelpers.getRaw(tvb, ICMPv6.identifier, relativeStackPosition)
        local icmpSeq = shanonHelpers.getRaw(tvb, ICMPv6.sequenceNumber, relativeStackPosition)
        local icmpData = shanonHelpers.getRest(tvb, ICMPv6.sequenceNumber, relativeStackPosition)

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
        local tmpChecksum = { ICMPv6.checksum() }
        local offset = tmpChecksum[relativeStackPosition].offset+tmpChecksum[relativeStackPosition].len
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
        local icmpPointer = shanonHelpers.getRaw(tvb, ICMPv6.pointer, relativeStackPosition)
        -- Data
        local icmpData = shanonHelpers.getRest(tvb, ICMPv6.pointer, relativeStackPosition)

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
        local icmpMTU = shanonHelpers.getRaw(tvb, ICMPv6.mtu, relativeStackPosition)
        local icmpData = shanonHelpers.getRest(tvb, ICMPv6.mtu, relativeStackPosition)

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
        --Get fields
        local ndpRaHopLimit = shanonHelpers.getRaw(tvb, ICMPv6.NDP.RA.hopLimit, relativeStackPosition)
        --Get 1 byte after the hop limit which contains the Router Advertisement flags
        local ndpRaFlags = shanonHelpers.getBytesAfterField(tvb, ICMPv6.NDP.RA.hopLimit, relativeStackPosition, 1)
        local ndpRaLifetime = shanonHelpers.getRaw(tvb, ICMPv6.NDP.RA.routerLifetime, relativeStackPosition)
        local ndpRaReachable = shanonHelpers.getRaw(tvb, ICMPv6.NDP.RA.reachableTime, relativeStackPosition)
        local ndpRaRetrans = shanonHelpers.getRaw(tvb, ICMPv6.NDP.RA.retransTime, relativeStackPosition)

        --Anonymized fields
        local ndpRaHopLimitAnon
        local ndpRaFlagsAnon
        local ndpRaLifetimeAnon
        local ndpRaReachableAnon
        local ndpRaRetransAnon

        --Anonymize fields
        ndpRaHopLimitAnon = ndpRaHopLimit
        ndpRaFlagsAnon = ndpRaFlags
        ndpRaLifetimeAnon = ndpRaLifetime
        ndpRaReachableAnon = ndpRaReachable
        ndpRaRetransAnon = ndpRaRetrans

        --Ann anonymized fields to ICMP message
        icmpMessage = icmpMessage .. ndpRaHopLimitAnon .. ndpRaFlagsAnon .. ndpRaLifetimeAnon .. ndpRaReachableAnon .. ndpRaRetransAnon

       --Add options to ICMP message
       icmpMessage = icmpMessage .. handleOptions(tvb)


    else
        --Handle other messages
        --Get data
        local icmpData = shanonHelpers.getRest(tvb, ICMPv6.checksum, relativeStackPosition)

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

-- Function to handle ICMPv6 options

function handleOptions(tvb)

    --The option payload
    local optionPayload = ""

    --Get list of present options
    local ndpOptionTypes = { ICMPv6.OPT.type()  }
    local ndpOptionLengths = { ICMPv6.OPT.length() }

    print "Options"

    for i,opt in ipairs(ndpOptionTypes) do

        print(tostring(opt.value))

        if opt.value == 3 then
            -- Prefix information
            -- Get fields
            local prefixType = shanonHelpers.getRaw(tvb, ICMPv6.OPT.type, i)
            local prefixOptionLength = shanonHelpers.getRaw(tvb, ICMPv6.OPT.length, i)
            --Using a count variable is necessary because there may be more of the same option
            local prefixLength = shanonHelpers.getRaw(tvb, ICMPv6.OPT.Prefix.PrefixLength, ICMPv6.OPT.Prefix.Count)
            --Get flags
            local prefixFlags = shanonHelpers.getBytesAfterField(tvb, ICMPv6.OPT.Prefix.PrefixLength, ICMPv6.OPT.Prefix.Count, 1)
            local prefixValidLifetime = shanonHelpers.getRaw(tvb, ICMPv6.OPT.Prefix.ValidLifetime, ICMPv6.OPT.Prefix.Count)
            local prefixPreferredLifetime = shanonHelpers.getRaw(tvb, ICMPv6.OPT.Prefix.PreferredLifetime, ICMPv6.OPT.Prefix.Count)
            --Get 4 bytes of reserved space
            local prefixReserved = shanonHelpers.getBytesAfterFieldWithOffset(tvb, ICMPv6.OPT.Prefix.PreferredLifetime, ICMPv6.OPT.Prefix.Count, 4, 4)
            local prefixPrefix = shanonHelpers.getRaw(tvb, ICMPv6.OPT.Prefix.Prefix, ICMPv6.OPT.Prefix.Count)

            --Anonymized fields
            local prefixTypeAnon
            local prefixOptionLengthAnon
            local prefixLengthAnon
            local prefixFlagsAnon
            local prefixValidLifetimeAnon
            local prefixPreferredLifetimeAnon
            local prefixReservedAnon
            local prefixPrefixAnon

            --Anonymize fields
            prefixTypeAnon = prefixType
            prefixOptionLengthAnon = prefixOptionLength
            prefixLengthAnon = prefixLength
            prefixFlagsAnon = prefixFlags
            prefixValidLifetimeAnon = prefixValidLifetime
            prefixPreferredLifetimeAnon = prefixPreferredLifetime
            prefixReservedAnon = prefixReserved
            prefixPrefixAnon = prefixPrefix

            --Add anonymized option to ICMP message
            optionPayload = optionPayload .. prefixTypeAnon .. prefixOptionLengthAnon .. prefixLengthAnon .. prefixFlagsAnon .. prefixValidLifetimeAnon
            optionPayload = optionPayload .. prefixPreferredLifetimeAnon .. prefixReservedAnon .. prefixPrefixAnon

            --Increment count
            ICMPv6.OPT.Prefix.Count = ICMPv6.OPT.Prefix.Count + 1

        elseif opt.value == 1 or opt.value == 2 then
            --Source/Target Link-layer Address
            --Get fields
            local llAddrType = shanonHelpers.getRaw(tvb, ICMPv6.OPT.type, i)
            local llAddrOptionLength = shanonHelpers.getRaw(tvb, ICMPv6.OPT.length, i)
            local llAddrLinkLayerAddress = shanonHelpers.getRaw(tvb, ICMPv6.OPT.LinkAddress.LinkAddress, ICMPv6.OPT.LinkAddress.Count)

            --Anonymized fields
            local llAddrTypeAnon
            local llAddrOptionLengthAnon
            local llAddrLinkLayerAddressAnon 

            --Anonymize fields
            llAddrTypeAnon = llAddrType
            llAddrOptionLengthAnon = llAddrOptionLength
            llAddrLinkLayerAddressAnon = llAddrLinkLayerAddress

            --Add anonymized option to ICMP message
            optionPayload = optionPayload .. llAddrTypeAnon .. llAddrOptionLengthAnon .. llAddrLinkLayerAddressAnon

            --Increment count
            ICMPv6.OPT.LinkAddress.Count = ICMPv6.OPT.LinkAddress.Count + 1

        elseif opt.value == 5 then
            -- MTU
            --Get fields
            local mtuType = shanonHelpers.getRaw(tvb, ICMPv6.OPT.type, i)
            local mtuOptionLength = shanonHelpers.getRaw(tvb, ICMPv6.OPT.length, i)
            local mtuReserved = shanonHelpers.getBytesAfterField(tvb, ICMPv6.OPT.length, i, 2)
            local mtuMtu = shanonHelpers.getRaw(tvb, ICMPv6.OPT.MTU.MTU, ICMPv6.OPT.MTU.Count)

            --Anonymized fields
            local mtuTypeAnon
            local mtuOptionLengthAnon
            local mtuReservedAnon
            local mtuMtuAnon

            --Anonymize fields
            mtuTypeAnon = mtuType
            mtuOptionLengthAnon = mtuOptionLength
            mtuReservedAnon = mtuReserved
            mtuMtuAnon = mtuMtu

            --Add anonymized option to ICMP message
            optionPayload = optionPayload .. mtuTypeAnon .. mtuOptionLengthAnon .. mtuReservedAnon .. mtuMtuAnon

            --Increment count
            ICMPv6.OPT.MTU.Count = ICMPv6.OPT.MTU.Count + 1
        
        elseif opt.value == 4 then
            --Redirect 
            --Get fields
            local redirectType = shanonHelpers.getRaw(tvb, ICMPv6.OPT.type, i)
            local redirectOptionLength = shanonHelpers.getRaw(tvb, ICMPv6.OPT.length, i)
            local redirectReserved = shanonHelpers.getBytesAfterField(tvb, ICMPv6.OPT.length, i, 6)
            local redirectPacket = shanonHelpers.getRaw(tvb, ICMPv6.OPT.Redirect.RedirectedPacket, ICMPv6.OPT.Redirect.Count)

            --Anonymized fields
            local redirectTypeAnon
            local redirectOptionLengthAnon
            local redirectReservedAnon
            local redirectPacketAnon

            --Anonymize fields
            redirectTypeAnon = redirectType
            redirectOptionLengthAnon = redirectOptionLength
            redirectReservedAnon = redirectReserved
            redirectPacketAnon = redirectPacket

            --Add anonymized option to ICMP message
            optionPayload = optionPayload .. redirectTypeAnon .. redirectOptionLengthAnon .. redirectReservedAnon .. redirectPacketAnon

            --Increment count
            ICMPv6.OPT.Redirect.Count = ICMPv6.OPT.Redirect.Count + 1

        end
    end
    
    --When we're done parsing options we need to reset the option counts
    ICMPv6.OPT.Prefix.Count = 1
    ICMPv6.OPT.LinkAddress.Count = 1
    ICMPv6.OPT.MTU.Count = 1
    ICMPv6.OPT.Redirect.Count = 1

    --Return the options
    return optionPayload
end

--Return the module table
return ICMPv6