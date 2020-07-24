--Functions for ICMPv6

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local ICMPv6={}

--The filter name is used when looking for instances of this protocol
ICMPv6.filterName = "icmpv6"

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
ICMPv6.relativeStackPosition = 1

--ICMP header fields
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
--Router solicitation has only reserved field and options so nothing to do here
--These show up in NDP Router Advertisement
ICMPv6.NDP.RA={}
ICMPv6.NDP.RA.hopLimit = Field.new("icmpv6.nd.ra.cur_hop_limit")
ICMPv6.NDP.RA.routerLifetime = Field.new("icmpv6.nd.ra.router_lifetime")
ICMPv6.NDP.RA.reachableTime = Field.new("icmpv6.nd.ra.reachable_time")
ICMPv6.NDP.RA.retransTime = Field.new("icmpv6.nd.ra.retrans_timer")
--These show up in NDP Neighbor Solicitation
ICMPv6.NDP.NS = {}
--Reserved field is marked as reserved here so we'll grab the bytes instead
ICMPv6.NDP.NS.Target = Field.new("icmpv6.nd.ns.target_address")
--These show up in NDP Neighbor Advertisement
ICMPv6.NDP.NA = {}
--The reserved field is part of the flag field here
ICMPv6.NDP.NA.Flags = Field.new("icmpv6.nd.na.flag") 
ICMPv6.NDP.NA.Target = Field.new("icmpv6.nd.na.target_address")
--These show up in NDP Redirect
ICMPv6.NDP.RD = {}
--4 reserved bytes before target address will be grabbed directly
ICMPv6.NDP.RD.targetAddress = Field.new("icmpv6.nd.rd.target_address")
ICMPv6.NDP.RD.destinationAddress = Field.new("icmpv6.rd.na.destination_address")

--Options
ICMPv6.OPT={}
ICMPv6.OPT.type = Field.new("icmpv6.opt.type")
ICMPv6.OPT.length = Field.new("icmpv6.opt.length")
--Prefix information
ICMPv6.OPT.Prefix = {}
ICMPv6.OPT.Prefix.PrefixLength = Field.new("icmpv6.opt.prefix.length")
--1 Byte flags will be extracted from TVB directly
ICMPv6.OPT.Prefix.ValidLifetime = Field.new("icmpv6.opt.prefix.valid_lifetime")
ICMPv6.OPT.Prefix.PreferredLifetime = Field.new("icmpv6.opt.prefix.preferred_lifetime")
--4 Bytes of reserved space will be extracted from TVB directly
ICMPv6.OPT.Prefix.Prefix = Field.new("icmpv6.opt.prefix")
--Source/Target Link-layer Address
ICMPv6.OPT.LinkAddress = {}
ICMPv6.OPT.LinkAddress.LinkAddress = Field.new("icmpv6.opt.linkaddr")
--MTU
ICMPv6.OPT.MTU = {}
--There are 2 bytes of reserved data that need to be fetched before this field
ICMPv6.OPT.MTU.MTU = Field.new("icmpv6.opt.mtu")
--Redirect
ICMPv6.OPT.Redirect = {}
--Redirected packet
--6 bytes are reserved and are fetched before this field
ICMPv6.OPT.Redirect.RedirectedPacket = Field.new("icmpv6.opt.redirected_packet")


function ICMPv6.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

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

    --Since different ICMPv6 message types may or may not have certain fields
    --these fields will not have the same relative stack position as the other ICMPv6 header fields
    --For example an ICMPv6 Echo Identifier from an ICMPv6 Echo that is contained within an ICMPv6 Destination Unreachable message
    --would have a position of 1 even though the ICMPv6 Echo message has a position of 2. 
    --Thus these values need to be retrieved not by using the index of the ICMPv6 message itself but by retrieving that value which is within
    --the area of the TVB where the ICMPv6 header currently being processed is

    --Start of ICMPv6 message
    local icmpv6Types = { ICMPv6.type() }
    local icmpv6Start = icmpv6Types[relativeStackPosition].offset

    --End of ICMPv6 message
    --For this we can simply use the start of the next message. Any ICMPv6 fields between the start of this and the next ICMPv6 message belong to this one
    local icmpv6End
    local icmpv6NextType = icmpv6Types[relativeStackPosition+1]
    if icmpv6NextType ~= nil then
        --If there is a next ICMPv6 message then the upper limit to where we should look for fields or options is there
        icmpv6End = icmpv6NextType.offset
    else
        --If there is no next ICMPv6 message the result will be nil in which case we just say it goes until the end of the captured buffer.
        icmpv6End = tvb:len()
    end


    --The rest is handled differently for different ICMP types
    local tmp = { ICMPv6.type() }
    local tmpType = tmp[relativeStackPosition].value
    if tmpType == 128 or tmpType == 129 then
        --Echo and Echo Reply
        --Get fields
        local count
        local icmpIds

        local icmpId = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.identifier, icmpv6Start, icmpv6End)
        local icmpSeq = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.sequenceNumber, icmpv6Start, icmpv6End)
        local icmpData = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMPv6.sequenceNumber, icmpv6Start, icmpv6End)

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
        --This method is used instead of using Field.new("icmp.unused") because there may be future uses for the unused field
        --but these uses aren't covered by this version of Shanon
        --The ICMPv6 checksum is always present so no need to account for it maybe not being here
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
        local icmpPointer = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.pointer, icmpv6Start, icmpv6End)
        -- Data
        local icmpData = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMPv6.pointer, icmpv6Start, icmpv6End)

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
        local icmpMTU = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.mtu, icmpv6Start, icmpv6End)
        local icmpData = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMPv6.mtu, icmpv6Start, icmpv6End)

        --Anonymized fields
        local icmpMTUAnon
        local icmpDataAnon

        --Anonymize fields
        icmpMTUAnon = icmpMTU
        icmpDataAnon = icmpData

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpMTUAnon .. icmpDataAnon
    elseif tmpType == 133 then
        --NDP Router Solicitation
        --Get fields
        local ndpRsReserved = shanonHelpers.getBytesAfterField(tvb, ICMPv6.checksum, relativeStackPosition, 4)

        --Anonymized fields
        local ndpRsReservedAnon

        --Anonymize fields
        ndpRsReservedAnon = ndpRsReserved

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. ndpRsReservedAnon

        --Add options to ICMP message
        icmpMessage = icmpMessage .. ICMPv6.handleOptions(tvb, icmpv6Start, icmpv6End)

    elseif tmpType == 134 then
        --NDP Router Advertisement
        --Get fields
        local ndpRaHopLimit = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.RA.hopLimit, icmpv6Start, icmpv6End)
        --Get 1 byte after the hop limit which contains the Router Advertisement flags
        local ndpRaFlags = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMPv6.NDP.RA.hopLimit, icmpv6Start, icmpv6End, 1)
        local ndpRaLifetime = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.RA.routerLifetime,  icmpv6Start, icmpv6End)
        local ndpRaReachable = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.RA.reachableTime,  icmpv6Start, icmpv6End)
        local ndpRaRetrans = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.RA.retransTime,  icmpv6Start, icmpv6End)

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

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. ndpRaHopLimitAnon .. ndpRaFlagsAnon .. ndpRaLifetimeAnon .. ndpRaReachableAnon .. ndpRaRetransAnon

       --Add options to ICMP message
       icmpMessage = icmpMessage .. ICMPv6.handleOptions(tvb, icmpv6Start, icmpv6End)
    elseif tmpType == 135 then
        --NDP Neighbor Solicitation
        --Get fields
        --Get reserved field as bytes
        local ndpNsReserved = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMPv6.checksum, icmpv6Start, icmpv6End, 4)
        local ndpNsTargetAddress = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.NS.Target, icmpv6Start, icmpv6End)

        --Anonymized fields
        local ndpNsReservedAnon
        local ndpNsTargetAddressAnon

        --Anonymize fields
        ndpNsReservedAnon = ndpNsReserved
        ndpNsTargetAddressAnon = ndpNsTargetAddress

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. ndpNsReservedAnon .. ndpNsTargetAddressAnon

        --Add options to ICMP message
        icmpMessage = icmpMessage .. ICMPv6.handleOptions(tvb, icmpv6Start, icmpv6End)

    elseif tmpType == 136 then
        --NDP Neighbor Advertisement
        --Get fields
        local ndpNaFlags = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.NA.Flags, icmpv6Start, icmpv6End)
        local ndpNaTargetAddress = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.NA.Target, icmpv6Start, icmpv6End)

        --Anonymized fields
        local ndpNaFlagsAnon
        local ndpNaTargetAddressAnon

        --Anonymize fields
        ndpNaFlagsAnon = ndpNaFlags
        ndpNaTargetAddressAnon = ndpNaTargetAddress

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. ndpNaFlagsAnon .. ndpNaTargetAddressAnon

        --Add options to ICMP message
        icmpMessage = icmpMessage .. ICMPv6.handleOptions(tvb, icmpv6Start, icmpv6End)

    elseif tmpType == 137 then
        --Redirect
        --Get fields
        local redirectReserved = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMPv6.checksum, icmpv6Start, icmpv6End, 4)
        local redirectTarget = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.RD.targetAddress, icmpv6Start, icmpv6End)
        local redirectDestination = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMPv6.NDP.RD.destinationAddress, icmpv6Start, icmpv6End)

        --Anonymized fields
        local redirectReservedAnon
        local redirectTargetAnon
        local redirectDestinationAnon

        --Anonymize fields
        redirectReservedAnon = redirectReserved
        redirectTargetAnon = redirectTarget
        redirectDestinationAnon = redirectDestination

        --Add anonymized fields to icmp message
        icmpMessage = icmpMessage .. redirectReservedAnon .. redirectTargetAnon .. redirectDestinationAnon

        --Add options to ICMP message
        icmpMessage = icmpMessage .. ICMPv6.handleOptions(tvb, icmpv6Start, icmpv6End)

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
function ICMPv6.handleOptions(tvb, icmpv6Start, icmpv6End)

    --The option payload
    local optionPayload = ""

    --Prefix information
    local prefixCount
    local prefixLengths

    --Try and grab a field that will be present if this option is present. This is both used and serves as a test if the option is present
    prefixCount, prefixLengths = shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.PrefixLength, icmpv6Start, icmpv6End)

    if prefixCount ~= 0 then
        local prefixOptionTypes 
        local prefixOptionLengths
        local prefixFlags
        local prefixValidLifetimes
        local prefixPreferredLifetimes
        local prefixReservedFields
        local prefixPrefixes
        
        --To get the option type and length we'll use the getBytesAfterFieldWithinBoundariesRaw function with a negative offset to get fields BEFORE the selected field
        prefixOptionTypes = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.PrefixLength, icmpv6Start, icmpv6End, 1, 2, prefixCount))
        prefixOptionLengths = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.PrefixLength, icmpv6Start, icmpv6End, 1, 1, prefixCount))
        --prefixLengths goes here in the order of field appearances.
        prefixFlags = select(2, shanonHelpers.getBytesAfterFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.PrefixLength, icmpv6Start, icmpv6End, 1, prefixCount))
        prefixValidLifetimes = select(2, shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.ValidLifetime, icmpv6Start, icmpv6End, prefixCount))
        prefixPreferredLifetimes = select(2, shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.PreferredLifetime, icmpv6Start, icmpv6End, prefixCount))
        prefixReservedFields = select(2, shanonHelpers.getBytesAfterFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.PreferredLifetime, icmpv6Start, icmpv6End, 4, prefixCount))
        prefixPrefixes = select(2, shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMPv6.OPT.Prefix.Prefix, icmpv6Start, icmpv6End, prefixCount))

        while prefixCount ~= 0 do
            --Anonymized fields
            local prefixOptionTypeAnon
            local prefixOptionLengthAnon
            local prefixLengthAnon
            local prefixFlagsAnon
            local prefixValidLifetimeAnon
            local prefixPreferredLifetimeAnon
            local prefixReservedAnon
            local prefixPrefixAnon

            --Anonymize fields
            prefixOptionTypeAnon = prefixOptionTypes[prefixCount]
            prefixOptionLengthAnon = prefixOptionLengths[prefixCount]
            prefixLengthAnon = prefixLengths[prefixCount]
            prefixFlagsAnon = prefixFlags[prefixCount]
            prefixValidLifetimeAnon = prefixValidLifetimes[prefixCount]
            prefixPreferredLifetimeAnon = prefixPreferredLifetimes[prefixCount]
            prefixReservedAnon = prefixReservedFields[prefixCount]
            prefixPrefixAnon = prefixPrefixes[prefixCount]

            --Subtract from count
            prefixCount = prefixCount - 1

            --Add to option payload
            optionPayload = optionPayload .. prefixOptionTypeAnon .. prefixOptionLengthAnon .. prefixLengthAnon .. prefixFlagsAnon .. prefixValidLifetimeAnon
            optionPayload = optionPayload .. prefixPreferredLifetimeAnon .. prefixReservedAnon .. prefixPrefixAnon
        end
    end

    --Source/Target Link-layer Address
    local llAddrCount
    local llAddrLinkLayerAddresses 

    llAddrCount, llAddrLinkLayerAddresses = shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMPv6.OPT.LinkAddress.LinkAddress, icmpv6Start, icmpv6End)

    if llAddrCount ~= 0 then
        local llAddrOptionTypes
        local llAddrOptionLengths

        llAddrOptionTypes = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.LinkAddress.LinkAddress, icmpv6Start, icmpv6End, 1, 2, llAddrCount))
        llAddrOptionLengths = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.LinkAddress.LinkAddress, icmpv6Start, icmpv6End, 1, 1, llAddrCount))

        while llAddrCount ~= 0 do
            --Anonymized fields
            local llAddrOptionTypeAnon
            local llAddrOptionLengthAnon
            local llAddrLinkLayerAddressAnon 

            --Anonymize fields
            llAddrOptionTypeAnon = llAddrOptionTypes[llAddrCount]
            llAddrOptionLengthAnon = llAddrOptionLengths[llAddrCount]
            llAddrLinkLayerAddressAnon = llAddrLinkLayerAddresses[llAddrCount]

            --Subtract from count
            llAddrCount = llAddrCount - 1

            --Add to option payload
            optionPayload = optionPayload .. llAddrOptionTypeAnon .. llAddrOptionLengthAnon .. llAddrLinkLayerAddressAnon
        end

    end

    --MTU

    local mtuCount
    local mtuMtus 

    mtuCount, mtuMtus = shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMPv6.OPT.MTU.MTU, icmpv6Start, icmpv6End)

    if mtuCount ~= 0 then
        local mtuOptionTypes
        local mtuOptionLengths
        local mtuReservedFields

        mtuOptionTypes = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.MTU.MTU, icmpv6Start, icmpv6End, 1, 4, mtuCount))
        mtuOptionLengths = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.MTU.MTU, icmpv6Start, icmpv6End, 1, 3, mtuCount))
        mtuReservedFields = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.MTU.MTU, icmpv6Start, icmpv6End, 2, 2, mtuCount))

        while mtuCount ~= 0 do

            --Anonymized fields
            local mtuOptionTypeAnon
            local mtuOptionLengthAnon
            local mtuReservedAnon
            local mtuMtuAnon

            --Anonymize fields
            mtuOptionTypeAnon = mtuTypes[mtuCount]
            mtuOptionLengthAnon = mtuOptionLengths[mtuCount]
            mtuReservedAnon = mtuReservedFields[mtuCount]
            mtuMtuAnon = mtuMtus[mtuCount]

            --Subtract from count
            mtuCount = mtuCount - 1

            --Add anonymized option to ICMP message
            optionPayload = optionPayload .. mtuOptionTypeAnon .. mtuOptionLengthAnon .. mtuReservedAnon .. mtuMtuAnon

        end

    end
    
    --Redirect
    local redirectCount
    local redirectPackets

    redirectCount, redirectPackets = shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMPv6.OPT.Redirect.RedirectedPacket, icmpv6Start, icmpv6End)

    if redirectCount ~= 0 then
        local redirectOptionTypes
        local redirectOptionLengths
        local redirectReservedFields

        redirectOptionTypes = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.Redirect.RedirectedPacket, icmpv6Start, icmpv6End, 1, 8, redirectCount))
        redirectOptionLengths = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.Redirect.RedirectedPacket, icmpv6Start, icmpv6End, 1, 7, redirectCount))
        redirectReservedFields = select(2, shanonHelpers.getBytesBeforeFieldWithinBoundariesRaw(tvb, ICMPv6.OPT.Redirect.RedirectedPacket, icmpv6Start, icmpv6End, 6, 6, redirectCount))

        while redirectCount ~= 0 do

            --Anonymized fields
            local redirectOptionTypeAnon
            local redirectOptionLengthAnon
            local redirectReservedAnon
            local redirectPacketAnon

            --Anonymize fields
            redirectOptionTypeAnon = redirectOptionTypes[redirectCount]
            redirectOptionLengthAnon = redirectOptionLengths[redirectCount]
            redirectReservedAnon = redirectReservedFields[redirectCount]
            redirectPacketAnon = redirectPackets[redirectCount]

            --Subtract from count
            redirectCount = redirectCount - 1

            --Add anonymized option to ICMP message
            optionPayload = optionPayload .. redirectOptionTypeAnon .. redirectOptionLengthAnon .. redirectReservedAnon .. redirectPacketAnon

        end
    end
    
    --Return the options
    return optionPayload
end

--Validator for ICMPv6 anonymization policy
function ICMPv6.validatePolicy(config)
    --TODO: Implement
end

--Return the module table
return ICMPv6