--Functions for IPv4

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"
local shanonPolicyValidators = require "shanonPolicyValidators"

--Module table
local IPv4={}

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

--The default anonymization policy for this protocol
IPv4.defaultPolicy = {
    default = {
        dscpEcn = "BlackMarker_MSB_8",
        length = "Recalculate",
        id = "BlackMarker_MSB_16",
        flagsAndOffset = "BlackMarker_MSB_16",
        ttl = "SetValue_64",
        checksum = "Recalculate",
        address = {
            default = {"CryptoPAN"}
        }
    }
}
--Policy validation functions
IPv4.policyValidation = {
    dscpEcn = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil),
    length = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Recalculate"}),
    id = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil),
    flagsAndOffset = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil),
    ttl = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateSetValue, nil),
    checksum = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Recalculate"}),
    address = shanonPolicyValidators.keyValidatedTableMultiValidatorFactory(shanonPolicyValidators.verifyIPv4Subnet, true, shanonPolicyValidators.isPossibleOption, {"Keep", "CryptoPAN"}, shanonPolicyValidators.validateBlackMarker, nil)
}
--Is the anonymization policy valid. This check need only be done once
IPv4.policyIsValid = false

function IPv4.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = IPv4.relativeStackPosition
    IPv4.relativeStackPosition = IPv4.relativeStackPosition - 1

    --If the policy is invalid (or on 1st run) we validate the policy
    if IPv4.policyIsValid == false then 
        IPv4.validatePolicy(config)
        IPv4.policyIsValid = true
    end

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

    --TODO: Check if anonymizedFrame is empty and apply a minimum payload

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
    --TODO: Should values that don't match be logged?
    ipVersionIhlAnon = ByteArray.new("45"):raw()

    if policy.dscpEcn == "Keep" then
        ipDscpEcnAnon = ipDscpEcn
    else
       local blackMarkerDirection, blackMarkerLength = shanonHelpers.getBlackMarkerValues(policy.dscpEcn)
       ipDscpEcnAnon = libAnonLua.black_marker(ipDscpEcn, blackMarkerLength, blackMarkerDirection)
    end

    if policy.length == "Keep" then
        ipLengthAnon = ipLengh
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
    --TODO: Should this stay this way or not?
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
    anonymizedFrame = ipVersionIhlAnon .. ipDscpEcnAnon .. ipLengthAnon .. ipIdAnon .. ipFlagsAnon .. 
    ipTtlAnon .. ipProtocolAnon .. ipChecksumAnon .. ipSrcAnon .. ipDstAnon .. anonymizedFrame

    --TODO: Deal with TCP and UDP checksums here

    --Return the anonymized frame
    return anonymizedFrame
end

function IPv4.validatePolicy(config)
    
    --Check if the config has an anonymizationPolicy
    shanonPolicyValidators.verifyPolicyExists(config)

    --Verify the default policy exists and its contents
    if config.anonymizationPolicy.ipv4 == nil then
        shanonHelpers.warnMissingPolicy("IPv4")
        config.anonymizationPolicy.ipv4 = IPv4.defaultPolicy
    else
        if config.anonymizationPolicy.ipv4.default == nil then
            shanonHelpers.writeLog(shanonHelpers.logWarn, "Default anonymization policy for unspecified IPv4 subnets not found. Using built-in default!")
            config.anonymizationPolicy.ipv4.default = IPv4.defaultPolicy.default
        end
        --Since the options in the config are named the same as the validators we can iterate through the validators and run them on the
        --similarly named options.
        --The only exception here is the address which needs some specific validation code
        for option, validator in pairs(IPv4.policyValidation) do
            if not validator(config.anonymizationPolicy.ipv4.default[option]) then
                shanonHelpers.warnUsingDefaultOption("IPv4", option, IPv4.defaultPolicy.default[option])
                config.anonymizationPolicy.ipv4.default[option] = IPv4.defaultPolicy.default[option]
            end
        end
    end

    --Verify each of the individual subnet policies and specified subnets are valid
    if config.anonymizationPolicy.ipv4.subnets ~= nil then 
        for subnet, policy in pairs(config.anonymizationPolicy.ipv4.subnets) do
            if next(policy) == nil then
                shanonHelpers.writeLog(shanonHelpers.logWarn, "Invalid subnet: " .. subnet .. " in IPv4 subnet config. Policy cannot be empty. Default settings will be applied to this subnet")
                config.anonymizationPolicy.ipv4.subnets[subnet] = nil
                --Lua has no continue...so annoying
                goto continueSubnetIPv4
            end
            if not shanonPolicyValidators.verifyIPv4Subnet(subnet) then
                shanonHelpers.writeLog(shanonHelpers.logWarn, "Invalid subnet: " .. subnet .. " in IPv4 subnet config. Default settings will be applied to this subnet")
                config.anonymizationPolicy.ipv4.subnets[subnet] = nil
                --Lua has no continue...so annoying
                goto continueSubnetIPv4
            else
                --Validate subnet settings here and copy from the config default (not the IPv4 defaults used before) if missing
                --This won't be logged as subnet settings are expected to differ partially from the default IPv4 settings
                --and it is valid for them not to have each option explicitly stated
                for option, validator in pairs(IPv4.policyValidation) do 
                    if policy[option] == nil then 
                        policy[option] = config.anonymizationPolicy.ipv4.default[option]                     
                    elseif not validator(policy[option]) then 
                        shanonHelpers.warnUsingDefaultOption("IPv4 subnet \"" .. subnet .. "\": ", option, config.anonymizationPolicy.ipv4.default[option])
                        policy[option] = config.anonymizationPolicy.ipv4.default[option]
                    end
                end
            end
            ::continueSubnetIPv4::
        end
    end

end

function IPv4.applyAnonymizationMethods(ipAddr, anonymizationMethods)
    --Apply the anonymization methods listed
    local tmpAnon = ipAddr
    local i = 1
    while (anonymizationMethods[i]~=nil) do
        if anonymizationMethods[i] == "Keep" then 
            tmpAnon = tmpAnon
        elseif anonymizationMethods[i] =="CryptoPAN" then 
            local anonStatus, anonResult = libAnonLua.cryptoPAN_anonymize_ipv4(tmpAnon)
            if anonStatus == -1 then 
                error("Failed to run CryptoPAN algorithm!")
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