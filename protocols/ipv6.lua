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

--Extension Headers
IPv6.EXTHDR = {}
--Store next headers in array to link them up correctly
IPv6.EXTHDR.NextHeaders = {}
IPv6.EXTHDR.NextHeadersLength = 0
--Store data separately because we'll need to insert next headers when reassembling
IPv6.EXTHDR.HeaderData = {}
IPv6.EXTHDR.HeaderDataLength = 0
--Destination Options
IPv6.EXTHDR.DST = {}
IPv6.EXTHDR.DST.Count = 1 --Count of Destination Options header
IPv6.EXTHDR.DST.NextHeaderRaw = ByteArray.new("3c"):raw() --Raw value of Next Header
IPv6.EXTHDR.DST.Length = Field.new("ipv6.dstopts.len")
--Data for this header will be grabbed and processed as an array of bytes
--Fragment Header
IPv6.EXTHDR.FRAG = {}
IPv6.EXTHDR.FRAG.Count = 1 
IPv6.EXTHDR.FRAG.NextHeaderRaw = ByteArray.new("2c"):raw() --Raw value of Next Header
IPv6.EXTHDR.FRAG.Reserved = Field.new("ipv6.fraghdr.reserved_octet")
IPv6.EXTHDR.FRAG.OffsetAndFlags = Field.new("ipv6.fraghdr.offset")
IPv6.EXTHDR.FRAG.Identification = Field.new("ipv6.fraghdr.ident")
--Hop-by-hop Options header
IPv6.EXTHDR.HOP = {}
IPv6.EXTHDR.HOP.Count = 1
IPv6.EXTHDR.HOP.NextHeaderRaw = ByteArray.new("00"):raw() -- Raw value of Next Header
IPv6.EXTHDR.HOP.Length = Field.new("ipv6.hopopts.len")
--Data for this header will be grabbed and processed as an array of bytes
--Routing Header
IPv6.EXTHDR.RT = {}
IPv6.EXTHDR.RT.Count = 1
IPv6.EXTHDR.RT.NextHeaderRaw = ByteArray.new("2b"):raw() -- Raw value of Next Header
IPv6.EXTHDR.RT.Length = Field.new("ipv6.routing.len")
IPv6.EXTHDR.RT.Type = Field.new("ipv6.routing.type")
IPv6.EXTHDR.RT.SegmentsLeft = Field.new("ipv6.routing.segleft")
--Rest of the header depends on different routing header types and will be treated as data


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

    --Handle Extension Headers here
    local nextHeaderValue
    local extensionHeaderData
    nextHeaderValue, extensionHeaderData = IPv6.handleExtensionHeaders(tvb)

    if nextHeaderValue ~= nil then
        --We got a valid result, set the IPv6 next header to the 1st option header in our option chain
        nextHeaderAnon = nextHeaderValue
    else
        --We got nothing
        --Leave the nextHeaderAnon field as is and set extensionHeaderData to an empty string so we concatenate nothing
        extensionHeaderData = ""
    end

    --Return the anonymization result
    return versionClassLabelAnon .. payloadLengthAnon .. nextHeaderAnon .. hopLimitAnon .. srcAnon .. dstAnon .. extensionHeaderData
end

function IPv6.handleExtensionHeaders(tvb)
    
    --Hop-by-hop Options
    extensionHeaderHopByHopLength = { IPv6.EXTHDR.HOP.Length() }
    --Destination Options
    extensionHeaderDestinationOptionsLength = { IPv6.EXTHDR.DST.Length() }
    --Routing Header
    extensionHeaderRoutingLength = { IPv6.EXTHDR.RT.Length() }
    --Fragment Header
    extensionHeaderFragmentReserved = { IPv6.EXTHDR.FRAG.Reserved() }
    
    while extensionHeaderHopByHopLength[IPv6.EXTHDR.HOP.Count] ~= nil do
        --Calculate length of data following length field in bytes
        --The length field is expressed in octets, not including the 1st octet. The Next Header and Length fields
        --are each one octet, or byte, long, so 6 of those bytes belong to data
        local hopByHopDataLength = extensionHeaderHopByHopLength[IPv6.EXTHDR.HOP.Count].value * 8 + 6

        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.HOP.NextHeaderRaw

        --Get fields
        local hopByHopLength = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.HOP.Length, IPv6.EXTHDR.HOP.Count)
        local hopByHopOpts = shanonHelpers.getBytesAfterField(tvb, IPv6.EXTHDR.HOP.Length, IPv6.EXTHDR.HOP.Count, hopByHopDataLength)
    
        --Anonymized fields
        local hopByHopLengthAnon
        local hopByHopOptsAnon

        --Anonymize fields
        hopByHopLengthAnon = hopByHopLength
        hopByHopOptsAnon = hopByHopOpts

        --Add fields to HeaderData array
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = hopByHopLengthAnon .. hopByHopOptsAnon

        --Increment Hop-By-Hop Options Count
        IPv6.EXTHDR.HOP.Count = IPv6.EXTHDR.HOP.Count + 1
    end

    while extensionHeaderDestinationOptionsLength[IPv6.EXTHDR.DST.Count] ~= nil do
        --Calculate length of data following length field in bytes
        --The length field is expressed in octets, not including the 1st octet. The Next Header and Length fields
        --are each one octet, or byte, long, so 6 of those bytes belong to data
        local dstOptDataLength = extensionHeaderDestinationOptionsLength[IPv6.EXTHDR.DST.Count].value * 8 + 6
        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.DST.NextHeaderRaw
        --Get fields
        local dstOptLength = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.DST.Length, IPv6.EXTHDR.DST.Count)
        local dstOptOpts = shanonHelpers.getBytesAfterField(tvb, IPv6.EXTHDR.DST.Length, IPv6.EXTHDR.DST.Count, dstOptDataLength)

        --Anonymized fields
        local dstOptLengthAnon
        local dstOptOptsAnon

        --Anonymize fields
        dstOptLengthAnon = dstOptLength
        dstOptOptsAnon = dstOptOpts

        --Add fields to HeaderData array
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = dstOptLengthAnon .. dstOptOptsAnon

        --Increment Destination Options Count
        IPv6.EXTHDR.DST.Count = IPv6.EXTHDR.DST.Count + 1
    end

    while extensionHeaderRoutingLength[IPv6.EXTHDR.RT.Count] ~=nil do
        --Calculate the length of data following the Segments Left field in bytes
        --We already fetch Next Header, Length, Routing Type and Segments Left so we add 4 instead of 6
        local routingDataLength = extensionHeaderRoutingLength[IPv6.EXTHDR.RT.Count].value * 8 + 4
        
        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.RT.NextHeaderRaw
        
        --Get fields
        local routingLength = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.RT.Length, IPv6.EXTHDR.RT.Count)
        local routingType = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.RT.Type, IPv6.EXTHDR.RT.Count)
        local routingSegmentsLeft = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.RT.SegmentsLeft, IPv6.EXTHDR.RT.Count)
        local routingData = shanonHelpers.getBytesAfterField(tvb, IPv6.EXTHDR.RT.SegmentsLeft, IPv6.EXTHDR.RT.Count, routingDataLength)

        --Anonymized fields
        local routingLengthAnon
        local routingTypeAnon
        local routingSegmentsLeftAnon
        local routingDataAnon

        --Anonymize fields
        routingLengthAnon = routingLength
        routingTypeAnon = routingType
        routingSegmentsLeftAnon = routingSegmentsLeft
        routingDataAnon = routingData

        --Add fields to HeaderData array
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = routingLengthAnon .. routingTypeAnon .. routingSegmentsLeftAnon .. routingDataAnon

        --Increment Routing Header Count
        IPv6.EXTHDR.RT.Count = IPv6.EXTHDR.RT.Count + 1
    end

    while extensionHeaderFragmentReserved[IPv6.EXTHDR.FRAG.Count] ~=nil do

        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.FRAG.NextHeaderRaw

        --Get fields
        local fragmentHeaderReserved = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.FRAG.Reserved, IPv6.EXTHDR.FRAG.Count)
        local fragmentHeaderOffsetAndFlags = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.FRAG.OffsetAndFlags, IPv6.EXTHDR.FRAG.Count)
        local fragmentHeaderIdentification = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.FRAG.Identification, IPv6.EXTHDR.FRAG.Count)
        
        --Anonymized fields
        local fragmentHeaderReservedAnon
        local fragmentHeaderOffseAndFlagsAnon
        local fragmentHeaderIdentificationAnon

        --Anonymize fields
        fragmentHeaderReservedAnon = fragmentHeaderReserved
        fragmentHeaderOffseAndFlagsAnon = fragmentHeaderOffsetAndFlags
        fragmentHeaderIdentificationAnon = fragmentHeaderIdentification

        --Add fields to HeaderDataArray
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = fragmentHeaderReservedAnon .. fragmentHeaderOffseAndFlagsAnon .. fragmentHeaderIdentificationAnon

        --Increment Fragment Header Count
        IPv6.EXTHDR.FRAG.Count = IPv6.EXTHDR.FRAG.Count + 1
    end
    
    --Reset all counts
    IPv6.EXTHDR.HOP.Count = 1
    IPv6.EXTHDR.DST.Count = 1
    IPv6.EXTHDR.RT.Count = 1
    IPv6.EXTHDR.FRAG.Count = 1

    --Assemble the full headers
    if IPv6.EXTHDR.NextHeadersLength ~= 0 then

        local extensionHeadersPayload = ""
        local IPv6NextHeaderValue = IPv6.EXTHDR.NextHeaders[1]

        for i=1,IPv6.EXTHDR.HeaderDataLength do
            -- Add NextHeader value of the next header we processed
            if IPv6.EXTHDR.NextHeaders[i+1] ~= nil then
                extensionHeadersPayload = extensionHeadersPayload .. IPv6.EXTHDR.NextHeaders[i+1]
            else
                --TODO: Pass the type of payload to the anonymize function and pass it here to assign correct next header value
                extensionHeadersPayload = extensionHeadersPayload .. ByteArray.new("00"):raw()
            end
            -- Add the processed header data
            extensionHeadersPayload = extensionHeadersPayload .. IPv6.EXTHDR.HeaderData[i]
        end
        --Return the next header value to set for the IPv6 next header field and the extension headers we processed
        return IPv6NextHeaderValue, extensionHeadersPayload
    else
        -- If the NextHeadersLength is 0 we have processed no options and we return nothing
        return nil, nil
    end
end

--Return the module table
return IPv6