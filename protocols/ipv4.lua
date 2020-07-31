--Functions for IPv4

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"
local shanonPolicyValidators = require "shanonPolicyValidators"

--Module table
local IPv4={}

--The filter name is used when looking for instances of this protocol
IPv4.filterName = "ip"

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

--Policy validation functions
IPv4.policyValidation = {
    dscp = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    ecn = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    id = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil),
    flagsAndOffset = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil),
    ttl = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateSetValue, {1, 255}),
    checksum = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Recalculate"}),
    address = shanonPolicyValidators.keyValidatedTableMultiValidatorFactory(shanonPolicyValidators.verifyIPv4Subnet, true, shanonPolicyValidators.isPossibleOption, {"Keep", "CryptoPAN"}, shanonPolicyValidators.validateBlackMarker, nil)
}

function IPv4.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

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
    --Local policy shorthand so we don't have to type a long policy table name every time.
    local policy

    --Check if we have a policy for subnets and if our source or destination addresses match any of the subnets specified in the policy
    if config.anonymizationPolicy.ipv4.subnets ~= nil then 
        for subnet, subnetPolicy in pairs(config.anonymizationPolicy.ipv4.subnets) do
            if libAnonLua.ip_in_subnet(ipSrc, subnet) or libAnonLua.ip_in_subnet(ipDst, subnet) then
                policy = subnetPolicy
                break
            end
        end
    end

    --If we didn't find a specific policy for this subnet, use the default
    if policy == nil then 
        policy = config.anonymizationPolicy.ipv4.default
    end

    --Version/IHL is set to a default 45
    ipVersionIhlAnon = ByteArray.new("45"):raw()

    --Apply masks to DSCP/ECN depending on the chosen policy options
    if policy.dscp == "Keep" and policy.ecn == "Keep" then 
        local mask = ByteArray.new("FF"):raw()
        ipDscpEcnAnon = libAnonLua.apply_mask(ipDscpEcn, mask)
    elseif policy.dscp == "Keep" and policy.ecn == "Zero" then
        local mask = ByteArray.new("FC"):raw()
        ipDscpEcnAnon = libAnonLua.apply_mask(ipDscpEcn, mask)
    elseif policy.dscp == "Zero" and policy.ecn == "Keep" then 
        local mask = ByteArray.new("03"):raw()
        ipDscpEcnAnon = libAnonLua.apply_mask(ipDscpEcn, mask)
    else
        local mask = ByteArray.new("00"):raw()
        ipDscpEcnAnon = libAnonLua.apply_mask(ipDscpEcn, mask)
    end

    --If the anonymized frame is empty, get the length value and generate a zero payload of same length
    --Otherwise recalculate the length to match
    if anonymizedFrame == "" then
        local ipPayloadLength = shanonHelpers.getValue(IPv4.totalLength, relativeStackPosition) - 20
        anonymizedFrame = shanonHelpers.generateZeroPayload(ipPayloadLength)
        ipLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame, 2, 20)
    else
        ipLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame, 2, 20)
    end
    
    if policy.id == "Keep" then 
        ipIdAnon = ipId
    else
        local blackMarkerDirection, blackMarkerLength = shanonHelpers.getBlackMarkerValues(policy.id)
        ipIdAnon = libAnonLua.black_marker(ipId, blackMarkerLength, blackMarkerDirection)
    end

    if policy.flagsAndOffset == "Keep" then
        ipFlagsAnon = ipFlags
    else
        local blackMarkerDirection, blackMarkerLength = shanonHelpers.getBlackMarkerValues(policy.flagsAndOffset)
        ipFlagsAnon = libAnonLua.black_marker(ipFlags, blackMarkerLength, blackMarkerDirection)
    end

    if policy.ttl == "Keep" then
        ipTtlAnon = ipTtl
    else
        ipTtlAnon = shanonHelpers.getSetValueBytes(policy.ttl,1)
    end
 
    --The protocol in use isn't anonymized
    ipProtocolAnon = ipProcotol

    --Used to check if source and destination were anonymized
    local srcAnonymized = false
    local dstAnonymized = false

    --Check if our addresses match any of the specified subnets and anonymize accordingly
    for subnet, anonymizationMethods in pairs(policy.address) do
        if subnet == "default" then 
            --Skip default here. If neither address is in any of the subnets then we'll default later
        else
            --Check if src is in the subnet
            if srcAnonymized == false and libAnonLua.ip_in_subnet(ipSrc, subnet) then 
                ipSrcAnon= IPv4.applyAnonymizationMethods(ipSrc, anonymizationMethods)
                srcAnonymized = true
            end
            --Check if dst is in the subnet
            if dstAnonymized == false and libAnonLua.ip_in_subnet(ipDst, subnet) then
                ipDstAnon = IPv4.applyAnonymizationMethods(ipDst, anonymizationMethods)
                dstAnonymized = true
            end
        end
        --End the loop if both have been anonymized
        if srcAnonymized and dstAnonymized then 
            break
        end
    end
    --If source or destination haven't been anonymized, apply the default
    if not srcAnonymized then
        ipSrcAnon = IPv4.applyAnonymizationMethods(ipSrc, policy.address.default)
    end

    if not dstAnonymized then 
        ipDstAnon = IPv4.applyAnonymizationMethods(ipDst, policy.address.default)
    end

    if policy.checksum == "Keep" then 
        ipChecksumAnon = ipChecksum
    else
        --Set checksum to 0. This is unnecessary as libAnonLua does it too, but better safe than sorry
        ipChecksumAnon = ByteArray.new("0000"):raw()
        --Assemble a temporary header with the values we have
        local ipv4HeaderTmp = ipVersionIhlAnon .. ipDscpEcnAnon .. ipLengthAnon .. ipIdAnon .. ipFlagsAnon .. 
        ipTtlAnon .. ipProtocolAnon .. ipChecksumAnon .. ipSrcAnon .. ipDstAnon 
        --Calculate che checksum based on this temporary header
        ipChecksumAnon = libAnonLua.calculate_ipv4_checksum(ipv4HeaderTmp)
    end

    --Write to the anonymized frame here
    local ipv4HeaderAnon =  ipVersionIhlAnon .. ipDscpEcnAnon .. ipLengthAnon .. ipIdAnon .. ipFlagsAnon .. 
    ipTtlAnon .. ipProtocolAnon .. ipChecksumAnon .. ipSrcAnon .. ipDstAnon

    local ipv4PacketAnon = ipv4HeaderAnon .. anonymizedFrame

    --Deal with TCP and UDP checksums here
    if ipProtocolAnon == ByteArray.new("11"):raw() and config.anonymizationPolicy.udp.checksum == "Recalculate" then --UDP
        local udpChecksum
        udpChecksum, anonymizedFrame = libAnonLua.calculate_tcp_udp_checksum(ipv4PacketAnon)
    elseif ipProtocolAnon == ByteArray.new("06"):raw() and config.anonymizationPolicy.tcp.checksum == "Recalculate" then --TCP
        local tcpChecksum
        tcpChecksum, anonymizedFrame = libAnonLua.calculate_tcp_udp_checksum(ipv4PacketAnon)
    end

    --Add the anonymized frame, now with checksum, to the ipv4Packet
    ipv4PacketAnon = ipv4HeaderAnon .. anonymizedFrame

    --Return the anonymized ipv4 packet
    return ipv4PacketAnon
end

function IPv4.validatePolicy(config)
    
    --Check if the config has an anonymizationPolicy
    shanonPolicyValidators.verifyPolicyExists(config)

    --Verify the default policy exists and its contents
    if config.anonymizationPolicy.ipv4 == nil then
        shanonHelpers.crashMissingPolicy("IPv4")
    else
        if config.anonymizationPolicy.ipv4.default == nil then

            shanonHelpers.crashWithError("Default anonymization policy for unspecified IPv4 subnets not found.")
        end
        --Since the options in the config are named the same as the validators we can iterate through the validators and run them on the
        --similarly named options.
        --The only exception here is the address which needs some specific validation code
        for option, validator in pairs(IPv4.policyValidation) do
            if not validator(config.anonymizationPolicy.ipv4.default[option]) then
                shanonHelpers.crashMissingOption("IPv4", option)
            end
        end
    end

    --Verify each of the individual subnet policies and specified subnets are valid
    if config.anonymizationPolicy.ipv4.subnets ~= nil then 
        for subnet, policy in pairs(config.anonymizationPolicy.ipv4.subnets) do
            if next(policy) == nil then
                shanonHelpers.crashWithError("Invalid subnet: " .. subnet .. " in IPv4 subnet config. Policy cannot be empty.")
            end
            if not shanonPolicyValidators.verifyIPv4Subnet(subnet) then
                shanonHelpers.crashWithError("Invalid subnet: " .. subnet .. " in IPv4 subnet config.")
            else
                --Validate subnet settings here and copy from the config default (not the IPv4 defaults used before) if missing
                --This won't be logged as subnet settings are expected to differ partially from the default IPv4 settings
                --and it is valid for them not to have each option explicitly stated
                --Invalid options will still result in the application ending execution with a warning, however
                for option, validator in pairs(IPv4.policyValidation) do 
                    if policy[option] == nil then 
                        policy[option] = config.anonymizationPolicy.ipv4.default[option]                     
                    elseif not validator(policy[option]) then 
                        shanonHelpers.crashMissingOption("IPv4 subnet \"" .. subnet .. "\": ", option)
                    end
                end
            end
        end
    end

end

function IPv4.applyAnonymizationMethods(ipAddr, anonymizationMethods)
    --Apply the anonymization methods listed
    local tmpAnon = ipAddr
    local i = 1
    while anonymizationMethods[i]~=nil do
        if anonymizationMethods[i] == "Keep" then 
            tmpAnon = tmpAnon
        elseif anonymizationMethods[i] =="CryptoPAN" then 
            local anonStatus, anonResult = libAnonLua.cryptoPAN_anonymize_ipv4(tmpAnon)
            if anonStatus == -1 then 
                shanonHelpers.crashWithError("Failed to run CryptoPAN algorithm during IPv4 anonymization!")
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

--Return the module table
return IPv4