--Functions for IPv6

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"
local shanonPolicyValidators = require "shanonPolicyValidators"

--Module table
local IPv6={}

--The filter name is used when looking for instances of this protocol
IPv6.filterName = "ipv6"

--A function to test if this is a faux protocol meant to indicate options of this protocol
function IPv6.fauxProtocols(protocolName)
    if protocolName:find("ipv6.") then
        return true
    else
        return false
    end
end

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

--The policy validation rules for IPv6
IPv6.policyValidation = 
{
    trafficClass = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}), 
    flowLabel = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    hopLimit = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateSetValue, {1, 255}),
    headers_hopByHop_keep = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"True", "False"}),
    headers_hopByHop_payload = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Zero", "Minimum", "Keep"}),
    headers_routing_keep = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"True", "False"}),
    headers_routing_payload = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Zero", "Minimum", "Keep"}),
    headers_fragment_fragmentOffset = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    headers_fragment_identification = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    headers_dstOpt_keep = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"True", "False"}),
    headers_dstOpt_payload = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Zero", "Minimum", "Keep"}),
    address = shanonPolicyValidators.keyValidatedTableMultiValidatorFactory(shanonPolicyValidators.verifyIPv6Subnet, true, shanonPolicyValidators.isPossibleOption, {"Keep", "CryptoPAN"}, shanonPolicyValidators.validateBlackMarker, nil)
}

function IPv6.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

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
    local policy

    --Check if we have a policy for subnets and if our source or destination addresses match and of the subnets specified in the policy
    if config.anonymizationPolicy.ipv6.subnets ~= nil then
        for subnet, subnetPolicy in pairs(config.anonymizationPolicy.ipv6.subnets) do
            if libAnonLua.ip_in_subnet(src, subnet) or libAnonLua.ip_in_subnet(dst, subnet) then
                policy = subnetPolicy
                break
            end
        end
    end
    
    --If we didn't find a specific policy for this subnet, use the default
    if policy == nil then 
        policy = config.anonymizationPolicy.ipv6.default
    end

    if policy.trafficClass == "Keep" and policy.flowLabel == "Keep" then
        local mask = ByteArray.new("FFFFFFFF"):raw()
        versionClassLabelAnon = libAnonLua.apply_mask(versionClassLabel, mask)
    elseif policy.trafficClass == "Keep" and policy.flowLabel == "Zero" then
        local mask = ByteArray.new("FFF00000"):raw()
        versionClassLabelAnon = libAnonLua.apply_mask(versionClassLabel, mask)
    elseif policy.trafficClass == "Zero" and policy.flowLabel == "Keep" then
        local mask = ByteArray.new("F00FFFFF"):raw()
        versionClassLabelAnon = libAnonLua.apply_mask(versionClassLabel, mask)
    else
        local mask = ByteArray.new("F0000000"):raw()
        versionClassLabelAnon = libAnonLua.apply_mask(versionClassLabel, mask)
    end
    
    --Set 1st 4 bits of versionClassLabelAnon to 6 for IPv6
    --Get 1st byte
    local versionClassLabelAnonFirstByte = versionClassLabelAnon:sub(1,1)
    --Turn it into a number by getting the decimal equivalent
    local versionClassLabelAnonFirstByteNumber = versionClassLabelAnonFirstByte:byte(1)
    --The rest of division by 16 is the lower 4 bits
    local versionClassLabelAnonFirstByteNumberLowerHalf = versionClassLabelAnonFirstByteNumber % 16
    --Add 96 to set the correct value of the 1st 4 bits for IPv6
    local correctFirstByte = versionClassLabelAnonFirstByteNumberLowerHalf + 96
    --Transform this into a byte again
    local correctFirstByteRaw = ByteArray.new(string.format("%02X", correctFirstByte)):raw()
    --Replace the 1st byte with this value
    versionClassLabelAnon = correctFirstByteRaw .. versionClassLabelAnon:sub(2)
    
    --Find the higher-layer protocol and try to set the next header if we recognize it
    --If there are no options we can parse or they're all skipped this ensures we're still pointing to the higher layer protocol
    --BUT in cases where we do not recognize the higher layer protocol (all but TCP, UDP and ICMPv6) that information is lost
    nextHeaderAnon = IPv6.getPayloadProtocolNextHeaderValue(protocolList, currentPosition)

    if policy.hopLimit == "Keep" then
        hopLimitAnon = hopLimit
    else
        hopLimitAnon = shanonHelpers.getSetValueBytes(policy.hopLimit, 1)
    end
    
    --Used to check if source and destination were anonymized
    local srcAnonymized = false
    local dstAnonymized = false

    --Check if our addresses match any of the specified subnets and anonymize accordigly
    for subnet, anonymizationMethods in pairs(policy.address) do
        if subnet == "default" then
            --Skip default here. If neither address is in any of the subnets then we'll default later
        else
            --Check if src is in the subnet
            if srcAnonymized == false and libAnonLua.ip_in_subnet(src, subnet) then 
                srcAnon = IPv6.applyAddressAnonymizationMethods(src, anonymizationMethods)
                srcAnonymized = true
            end
            --Check if dst is in the subnet
            if dstAnonymized == false and libAnonLua.ip_in_subnet(dst, subnet) then
                dstAnon = IPv6.applyAddressAnonymizationMethods(dst, anonymizationMethods)
                dstAnonymized = true
            end
            --End the loop if both have been anonymized
            if srcAnonymized and dstAnonymized then 
                break
            end
        end
    end
    --If source or destination haven't been anonymized, apply the default
    if not srcAnonymized then 
        srcAnon = IPv6.applyAddressAnonymizationMethods(src, policy.address.default)
    end

    if not dstAnonymized then 
        dstAnon = IPv6.applyAddressAnonymizationMethods(dst, policy.address.default)
    end
    
    --Handle Extension Headers here
    local nextHeaderValue
    local extensionHeaderData
    nextHeaderValue, extensionHeaderData = IPv6.handleExtensionHeaders(tvb, relativeStackPosition, policy, protocolList, currentPosition)

    if nextHeaderValue ~= nil then
        --We got a valid result, set the IPv6 next header to the 1st option header in our option chain
        nextHeaderAnon = nextHeaderValue
    else
        --We got nothing
        --Leave the nextHeaderAnon field as is and set extensionHeaderData to an empty string so we concatenate nothing
        extensionHeaderData = ""
    end

     --If the anonymized frame is empty, get the length value and generate a zero payload of same length
    --Otherwise recalculate the length to match
    if anonymizedFrame == "" then 
        --Generate a payload that is equal to the payload length minus any extension headers we processed and put it in the anonymized frame
        local ipv6PayloadLength = shanonHelpers.getValue(IPv6.payload_length) - extensionHeaderData:len()
        anonymizedFrame = shanonHelpers.generateZeroPayload(ipv6PayloadLength)
        payloadLengthAnon = payloadLength
    else 
        --Calculate the length based on the anonymized frame we received
        payloadLengthAnon = shanonHelpers.getLengthAsBytes(extensionHeaderData .. anonymizedFrame, 2)
    end

    --Assemble the fully anonymized IPv6 packet
    local ipv6HeaderAndOptionsAnon = versionClassLabelAnon .. payloadLengthAnon .. nextHeaderAnon .. hopLimitAnon .. srcAnon .. dstAnon .. extensionHeaderData
    local ipv6PacketAnon = ipv6HeaderAndOptionsAnon .. anonymizedFrame

    --Deal with TCP, UDP and ICMPv6 checksums here
    local payloadProtoName = IPv6.getPayloadProtocolName(protocolList, currentPosition)

    if payloadProtoName == "icmpv6" and config.anonymizationPolicy.icmpv6.checksum == "Recalculate" then 
        local icmpv6Checksum
        icmpv6Checksum, ipv6PacketAnon = libAnonLua.calculate_icmpv6_checksum(ipv6PacketAnon)
    elseif payloadProtoName == "tcp" and config.anonymizationPolicy.tcp.checksum == "Recalculate" then 
        local checksumAnon, anonymizedFrame = libAnonLua.calculate_tcp_udp_checksum(ipv6PacketAnon)
        ipv6PacketAnon = ipv6HeaderAndOptionsAnon .. anonymizedFrame
    elseif payloadProtoName == "udp" and config.anonymizationPolicy.udp.checksum == "Recalculate" then 
        local checksumAnon, anonymizedFrame = libAnonLua.calculate_tcp_udp_checksum(ipv6PacketAnon)
        ipv6PacketAnon = ipv6HeaderAndOptionsAnon .. anonymizedFrame
    end

    --Return the anonymization result
    return ipv6PacketAnon
end

function IPv6.handleExtensionHeaders(tvb, relativeStackPosition, policy, protocolList, currentPosition)

    --Determine the boundaries of where extension headers can be located in the tvb
    --This is to prevent parsing options that belong to other, encapsulated IPv6 headers

    --Get current IPv6 header start
    local versionClassLabel = { IPv6.version_class_label() }
    local length = { IPv6.payload_length() }
    local dst = { IPv6.dst() }
    local ipv6LowerLimit = versionClassLabel[relativeStackPosition].offset
    --Get the upper instance header start (if exists)
    local ipv6UpperLimit
    local encapsulatedVersionClassLabel = versionClassLabel[relativeStackPosition + 1]
    if encapsulatedVersionClassLabel ~= nil then
        --If a next encapsulated instance of IPv6 exists then our upper byte limit is the start of this instance
        ipv6UpperLimit = encapsulatedVersionClassLabel.offset
    else
        --Otherwise there is none and our upper limit can be calculated using the IPv6 payload length
        ipv6UpperLimit = dst[relativeStackPosition].offset + dst[relativeStackPosition].len + length[relativeStackPosition].value
    end

    --Set these values back to their proper defaults. 
    IPv6.EXTHDR.NextHeaders = {}
    IPv6.EXTHDR.NextHeadersLength = 0
    IPv6.EXTHDR.HeaderData = {}
    IPv6.EXTHDR.HeaderDataLength = 0

    --An empty payload to use with an option of minimum length
    local minimumOptionPayload = ByteArray.new("000000000000"):raw()
    local minimumOptionLength = ByteArray.new("07"):raw()

    --Hop-by-hop Options
    local extensionHeaderHopByHopLength = { IPv6.EXTHDR.HOP.Length() }
    --Destination Options
    local extensionHeaderDestinationOptionsLength = { IPv6.EXTHDR.DST.Length() }
    --Routing Header
    local extensionHeaderRoutingLength = { IPv6.EXTHDR.RT.Length() }
    --Fragment Header
    local extensionHeaderFragmentReserved = { IPv6.EXTHDR.FRAG.Reserved() }
    
    while extensionHeaderHopByHopLength[IPv6.EXTHDR.HOP.Count] ~= nil do

        --Check if we should skip this
        if policy.headers_hopByHop_keep == "False" then 
            break;
        end

        --Local variables need to be declared here because goto cannot jump into the scope of a local variable in Lua
        local hopByHopDataLength
        local hopByHopLength
        local hopByHopOpts

        --Anonymized fields
        local hopByHopLengthAnon
        local hopByHopOptsAnon

        --Check if within boundaries
        if extensionHeaderHopByHopLength[IPv6.EXTHDR.HOP.Count].offset < ipv6LowerLimit then
            --We're in a previous header BUT we can still keep searching
            goto continueHopByHop
        elseif extensionHeaderHopByHopLength[IPv6.EXTHDR.HOP.Count].offset > ipv6UpperLimit then
            --We're beyond the options of this header, break the loop
            break
        end
        --Calculate length of data following length field in bytes
        --The length field is expressed in octets, not including the 1st octet. The Next Header and Length fields
        --are each one octet, or byte, long, so 6 of those bytes belong to data
        hopByHopDataLength = extensionHeaderHopByHopLength[IPv6.EXTHDR.HOP.Count].value * 8 + 6

        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.HOP.NextHeaderRaw

        --Get fields
        hopByHopLength = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.HOP.Length, IPv6.EXTHDR.HOP.Count)
        hopByHopOpts = shanonHelpers.getBytesAfterField(tvb, IPv6.EXTHDR.HOP.Length, IPv6.EXTHDR.HOP.Count, hopByHopDataLength)

        --Anonymize fields
        if policy.headers_hopByHop_payload == "Keep" then 
            hopByHopLengthAnon = hopByHopLength
            hopByHopOptsAnon = hopByHopOpts
        elseif policy.headers_hopByHop_payload == "Minimum" then 
            hopByHopLengthAnon = minimumOptionLength
            hopByHopOptsAnon = minimumOptionPayload
        else 
            --Zero
            hopByHopLengthAnon = hopByHopLength
            hopByHopOptsAnon = shanonHelpers.generateZeroPayload(hopByHopOpts:len())
        end
        
        --Add fields to HeaderData array
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = hopByHopLengthAnon .. hopByHopOptsAnon

        --Lua has no continue statement so we use a label and goto. Nice work Lua developers! 
        ::continueHopByHop::
        --Increment Hop-By-Hop Options Count
        IPv6.EXTHDR.HOP.Count = IPv6.EXTHDR.HOP.Count + 1
    end

    while extensionHeaderDestinationOptionsLength[IPv6.EXTHDR.DST.Count] ~= nil do

        --Check if we should skip this
        if policy.headers_dstOpt_keep == "False" then 
            break;
        end

        --Local variables need to be declared here because goto cannot jump into the scope of a local variable in Lua
        local dstOptDataLength
        local dstOptLength
        local dstOptOpts

        --Anonymized fields
        local dstOptLengthAnon
        local dstOptOptsAnon

        --Check if within boundaries
        if extensionHeaderDestinationOptionsLength[IPv6.EXTHDR.HOP.Count].offset < ipv6LowerLimit then
            --We're in a previous header BUT we can still keep searching
            goto continueDstOpt
        elseif extensionHeaderDestinationOptionsLength[IPv6.EXTHDR.HOP.Count].offset > ipv6UpperLimit then
            --We're beyond the options of this header, break the loop
            break
        end
        --Calculate length of data following length field in bytes
        --The length field is expressed in octets, not including the 1st octet. The Next Header and Length fields
        --are each one octet, or byte, long, so 6 of those bytes belong to data
        dstOptDataLength = extensionHeaderDestinationOptionsLength[IPv6.EXTHDR.DST.Count].value * 8 + 6
        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.DST.NextHeaderRaw
        --Get fields
        dstOptLength = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.DST.Length, IPv6.EXTHDR.DST.Count)
        dstOptOpts = shanonHelpers.getBytesAfterField(tvb, IPv6.EXTHDR.DST.Length, IPv6.EXTHDR.DST.Count, dstOptDataLength) 

        --Anonymize fields
        if policy.headers_dstOpt_payload == "Keep" then 
            dstOptLengthAnon = dstOptLength
            dstOptOptsAnon = dstOptOpts
        elseif policy.headers_dstOpt_payload == "Minimum" then 
            dstOptLengthAnon = minimumOptionLength
            dstOptOptsAnon = minimumOptionPayload
        else 
            --Zero
            dstOptLengthAnon = dstOptLength
            dstOptOptsAnon = shanonHelpers.generateZeroPayload(dstOptOpts:len())
        end

        --Add fields to HeaderData array
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = dstOptLengthAnon .. dstOptOptsAnon

        --Lua has no continue statement so we use a label and goto. Nice work Lua developers! 
        ::continueDstOpt::
        --Increment Destination Options Count
        IPv6.EXTHDR.DST.Count = IPv6.EXTHDR.DST.Count + 1
    end

    while extensionHeaderRoutingLength[IPv6.EXTHDR.RT.Count] ~=nil do

        --Check if we should skip this
        if policy.headers_routing_keep == "False" then 
            break;
        end

        --Local variables need to be declared here because goto cannot jump into the scope of a local variable in Lua
        local routingDataLength
        local routingLength
        local routingType
        local routingSegmentsLeft
        local routingData

        --Anonymized fields
        local routingLengthAnon
        local routingTypeAnon
        local routingSegmentsLeftAnon
        local routingDataAnon

        --Check if within boundaries
        if extensionHeaderRoutingLength[IPv6.EXTHDR.HOP.Count].offset < ipv6LowerLimit then
            --We're in a previous header BUT we can still keep searching
            goto continueRouting
        elseif extensionHeaderRoutingLength[IPv6.EXTHDR.HOP.Count].offset > ipv6UpperLimit then
            --We're beyond the options of this header, break the loop
            break
        end
        --Calculate the length of data following the Segments Left field in bytes
        --We already fetch Next Header, Length, Routing Type and Segments Left so we add 4 instead of 6
        routingDataLength = extensionHeaderRoutingLength[IPv6.EXTHDR.RT.Count].value * 8 + 4
        
        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.RT.NextHeaderRaw
        
        --Get fields
        routingLength = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.RT.Length, IPv6.EXTHDR.RT.Count)
        routingType = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.RT.Type, IPv6.EXTHDR.RT.Count)
        routingSegmentsLeft = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.RT.SegmentsLeft, IPv6.EXTHDR.RT.Count)
        routingData = shanonHelpers.getBytesAfterField(tvb, IPv6.EXTHDR.RT.SegmentsLeft, IPv6.EXTHDR.RT.Count, routingDataLength)

        --Anonymize fields
        --Type is always preserved
        routingTypeAnon = routingType

        if policy.headers_routing_payload == "Keep" then 
            routingLengthAnon = routingLength    
            routingSegmentsLeftAnon = routingSegmentsLeft
            routingDataAnon = routingData
        elseif policy.headers_routing_payload == "Minimum" then 
            routingLengthAnon = minimumOptionLength;
            routingSegmentsLeftAnon = ByteArray.new("00"):raw() --Zero segments
            routingDataAnon = ByteArray.new("00000000"):raw() --4 bytes to create a total length of 8 octets
        else 
            --Zero
            routingLengthAnon = routingLength
            routingSegmentsLeftAnon = routingSegmentsLeft
            routingDataAnon = shanonHelpers.generateZeroPayload(routingData:len())
        end

        --Add fields to HeaderData array
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = routingLengthAnon .. routingTypeAnon .. routingSegmentsLeftAnon .. routingDataAnon

        --Lua has no continue statement so we use a label and goto. Nice work Lua developers! 
        ::continueRouting::
        --Increment Routing Header Count
        IPv6.EXTHDR.RT.Count = IPv6.EXTHDR.RT.Count + 1
    end

    while extensionHeaderFragmentReserved[IPv6.EXTHDR.FRAG.Count] ~=nil do

        --Local variables need to be declared here because goto cannot jump into the scope of a local variable in Lua
        local fragmentHeaderReserved
        local fragmentHeaderOffseAndFlags
        local fragmentHeaderIdentification
        local mask

        --Anonymized fields
        local fragmentHeaderReservedAnon
        local fragmentHeaderOffseAndFlagsAnon
        local fragmentHeaderIdentificationAnon

        --Check if within boundaries
        if extensionHeaderFragmentReserved[IPv6.EXTHDR.FRAG.Count].offset < ipv6LowerLimit then
            --We're in a previous header BUT we can still keep searching
            goto continueFragmentHeader
        elseif extensionHeaderFragmentReserved[IPv6.EXTHDR.FRAG.Count].offset > ipv6UpperLimit then
            --We're beyond the options of this header, break the loop
            break
        end
        --Set the NextHeaders field to this header's next header value
        IPv6.EXTHDR.NextHeadersLength = IPv6.EXTHDR.NextHeadersLength + 1
        IPv6.EXTHDR.NextHeaders[IPv6.EXTHDR.NextHeadersLength] = IPv6.EXTHDR.FRAG.NextHeaderRaw

        --Get fields
        fragmentHeaderReserved = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.FRAG.Reserved, IPv6.EXTHDR.FRAG.Count)
        fragmentHeaderOffsetAndFlags = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.FRAG.OffsetAndFlags, IPv6.EXTHDR.FRAG.Count)
        fragmentHeaderIdentification = shanonHelpers.getRaw(tvb, IPv6.EXTHDR.FRAG.Identification, IPv6.EXTHDR.FRAG.Count)
        
        --Anonymize fields
        --The reserved field should be all zeroes so we zero it out
        fragmentHeaderReservedAnon = shanonHelpers.generateZeroPayload(1)
        if policy.headers_fragment_fragmentOffset == "Keep" then 
            mask = ByteArray.new("FFF9"):raw()
            fragmentHeaderOffseAndFlagsAnon = libAnonLua.apply_mask(fragmentHeaderOffsetAndFlags, mask)
        else
            --Zero
            mask = ByteArray.new("0001"):raw()
            fragmentHeaderOffseAndFlagsAnon = libAnonLua.apply_mask(fragmentHeaderOffsetAndFlags, mask)
        end
        
        if policy.headers_fragment_identification == "Keep" then
            fragmentHeaderIdentificationAnon = fragmentHeaderIdentification
        else 
            --Generate 4 bytes of zeroes to replace this instead
            fragmentHeaderIdentificationAnon = shanonHelpers.generateZeroPayload(4)
        end

        --Add fields to HeaderDataArray
        IPv6.EXTHDR.HeaderDataLength = IPv6.EXTHDR.HeaderDataLength + 1
        IPv6.EXTHDR.HeaderData[IPv6.EXTHDR.HeaderDataLength] = fragmentHeaderReservedAnon .. fragmentHeaderOffseAndFlagsAnon .. fragmentHeaderIdentificationAnon

        --Lua has no continue statement so we use a label and goto. Nice work Lua developers! 
        ::continueFragmentHeader::
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
                local nxtValue = IPv6.getPayloadProtocolNextHeaderValue(protocolList, currentPosition)
                extensionHeadersPayload = extensionHeadersPayload .. nxtValue
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

function IPv6.validatePolicy(config)
    --Check if the config has an anonymizationPolicy
    shanonPolicyValidators.verifyPolicyExists(config)

    --Verify the default policy exists and its contents
    if config.anonymizationPolicy.ipv6 == nil then
        shanonHelpers.crashMissingPolicy("IPv6")
        config.anonymizationPolicy.ipv6 = IPv6.defaultPolicy
    else
        if config.anonymizationPolicy.ipv6.default == nil then
            shanonHelpers.crashWithError("Default anonymization policy for unspecified IPv6 subnets not found.")
            config.anonymizationPolicy.ipv6.default = IPv6.defaultPolicy.default
        end
        --Iterate through validators to validate policy elements
        for option, validator in pairs(IPv6.policyValidation) do
            if not validator(config.anonymizationPolicy.ipv6.default[option]) then
                shanonHelpers.crashMissingOption("IPv6", option)
            end
        end
    end

    --Verify each of the individual subnet policies and specified subnets are valid
    if config.anonymizationPolicy.ipv6.subnets ~= nil then 
        for subnet, policy in pairs(config.anonymizationPolicy.ipv6.subnets) do
            if next(policy) == nil then 
                shanonHelpers.crashWithError("Invalid subnet: " .. subnet .. " in IPv6 subnet config. Policy cannot be empty.")
            end
            if not shanonPolicyValidators.verifyIPv6Subnet(subnet) then 
                shanonHelpers.crashWithError("Invalid subnet: " .. subnet .. " in IPv6 subnet config.")
            else
                for option, validator in pairs(IPv6.policyValidation) do
                    if policy[option] == nil then
                        --If not specified, silently replace
                        policy[option] = config.anonymizationPolicy.ipv6.default[option]
                    elseif not validator(policy[option]) then
                        --If specified, but invalid, crash
                        shanonHelpers.crashMissingOption("IPv6 subnet \"" .. subnet .. "\": ", option)
                    end
                end
            end
            ::continueSubnetIPv6::
        end

    end

end

function IPv6.applyAddressAnonymizationMethods(ipv6Addr, anonymizationMethods)
    local tmpAnon = ipv6Addr
    local i = 1
    while anonymizationMethods[i] ~= nil do
        if anonymizationMethods[i] == "Keep" then 
            tmpAnon = tmpAnon
        elseif anonymizationMethods[i] == "CryptoPAN" then
            local anonStatus, anonResult = libAnonLua.cryptoPAN_anonymize_ipv6(tmpAnon)
            if anonStatus == -1 then 
                shanonHelpers.crashWithError("Failed to run CryptoPAN algorithm during IPv6 anonymization!")
            else
                tmpAnon = anonResult
            end
        else
            --Black marker
            local blackMarkerDirection, blackMarkerLength = shanonHelpers.getBlackMarkerValues(anonymizationMethods[i])
            tmpAnon = libAnonLua.black_marker(tmpAnon, blackMarkerLength, blackMarkerDirection)
        end
        --Increment position
        i = i + 1
    end
    return tmpAnon
end

function IPv6.getPayloadProtocolNextHeaderValue(protocolList, currentPosition)

    local proto = IPv6.getPayloadProtocolName(protocolList, currentPosition)
    local nxtValue

    if proto == "icmpv6" then
        nxtValue = ByteArray.new("3A"):raw()
    elseif proto == "tcp" then 
        nxtValue = ByteArray.new("06"):raw()
    elseif proto == "udp" then 
        nxtValue = ByteArray.new("11"):raw()
    else 
        --If we don't have a type we can process, 3B (No next header) will be used instead
        nxtValue = ByteArray.new("3B"):raw()
    end

    return nxtValue
end

function IPv6.getPayloadProtocolName(protocolList, currentPosition)
    --Point to next position
    local position = currentPosition + 1

    --Reach the first protocol that doesn't start with ipv6.
    while protocolList[position]:find("ipv6.") do
        position = position + 1
    end

    --Get the protocol number for the protocol name for known protocols
    local protoName = protocolList[position]

    return protoName
end

--Return the module table
return IPv6