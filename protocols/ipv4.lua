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
        ttl = "SetValue_64",
        checksum = "Recalculate",
        address = "CryptoPAN"
    }
}
--Policy validation functions
IPv4.policyValidation = {
    dscpEcn = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil),
    length = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Recalculate"}),
    ttl = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateSetValue, nil),
    checksum = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Recalculate"}),
    address = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "CryptoPAN"}, shanonPolicyValidators.validateBlackMarker, nil)
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
    ipVersionIhlAnon = ipVersionIhl
    ipDscpEcnAnon = ipDscpEcn
    ipLengthAnon = ipLengh
    ipIdAnon = ipId
    ipFlagsAnon = ipFlags
    ipTtlAnon = ipTtl
    ipProtocolAnon = ipProcotol
    ipChecksumAnon = ipChecksum
    ipSrcAnon = ipSrc
    ipDstAnon = ipDst

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
            shanonHelpers.writeLog(shanonHelpers.logWarn, "Default anonymization policy for unspecified IPv4 subnets not found. Using default!")
            config.anonymizationPolicy.ipv4.default = IPv4.defaultPolicy.default
        end
        if not IPv4.policyValidation.dscpEcn(config.anonymizationPolicy.ipv4.default.dscpEcn) then 
            shanonHelpers.warnUsingDefaultOption("IPv4", "DSCP/ECN", Ethernet.defaultPolicy.dscpEcn)
            config.anonymizationPolicy.ipv4.default.dscpEcn = IPv4.defaultPolicy.default.dscpEcn
        end
        if not IPv4.policyValidation.length(config.anonymizationPolicy.ipv4.default.length) then
            shanonHelpers.warnUsingDefaultOption("IPv4", "length", Ethernet.defaultPolicy.length)
            config.anonymizationPolicy.ipv4.default.length = IPv4.defaultPolicy.default.length
        end
        if not IPv4.policyValidation.ttl(config.anonymizationPolicy.ipv4.default.ttl) then
            shanonHelpers.warnUsingDefaultOption("IPv4", "TTL", Ethernet.defaultPolicy.ttl)
            config.anonymizationPolicy.ipv4.default.ttl = IPv4.defaultPolicy.default.ttl 
        end
        if not IPv4.policyValidation.checksum(config.anonymizationPolicy.ipv4.default.checksum) then
            shanonHelpers.warnUsingDefaultOption("IPv4", "checksum", Ethernet.defaultPolicy.checksum)
            config.anonymizationPolicy.ipv4.default.checksum = IPv4.defaultPolicy.default.checksum
        end
        if not IPv4.policyValidation.address(config.anonymizationPolicy.ipv4.address) then
            shanonHelpers.warnUsingDefaultOption("IPv4", "address", Ethernet.defaultPolicy.address)
            config.anonymizationPolicy.ipv4.default.address = IPv4.defaultPolicy.default.address
        end
    end

    --Verify each of the individual subnet policies and specified subnets are valid
    if config.anonymizationPolicy.ipv4.subnets ~= nil then 
        for subnet, policy in pairs(config.anonymizationPolicy.ipv4.subnets) do
            if not shanonPolicyValidators.verifyIPv4Subnet(subnet) then
                shanonHelpers.writeLog(shanonHelpers.logWarn, "Invalid subnet: " .. subnet .. "  in IPv4 config. Default settings will be applied to this subnet")
                table.remove(config.anonymizationPolicy.ipv.subnets, subnet)
                --Lua has no continue...so annoying
                goto continueSubnet
            else
                --Validate subnet settings here and copy from the config default (not the IPv4 defaults used before) if missing
                --This won't be logged as subnet settings are expected to differ partially from the default IPv4 settings
                --and it is valid for them not to have each option explicitly stated
                if not IPv4.policyValidation.dscpEcn(policy.dscpEcn) then 
                    policy.dscpEcn = config.anonymizationPolicy.ipv4.default.dscpEcn
                end
                if not IPv4.policyValidation.length(policy.length) then
                    policy.length = config.anonymizationPolicy.ipv4.default.length
                end
                if not IPv4.policyValidation.ttl(policy.ttl) then
                    policy.ttl = config.anonymizationPolicy.ipv4.default.ttl
                end
                if not IPv4.policyValidation.checksum(policy.checksum) then
                    policy.checksum = config.anonymizationPolicy.ipv4.default.checksum
                end
                if not IPv4.policyValidation.address(policy.address) then
                    policy.address = config.anonymizationPolicy.ipv4.default.address
                end
            end
            ::continueSubnet::
        end
    end

end


--Return the module table
return IPv4