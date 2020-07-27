--Functions for UDP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"
local shanonPolicyValidators = require "shanonPolicyValidators"

--Module table
local UDP={}

--The filter name is used when looking for instances of this protocol
UDP.filterName = "udp"

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
UDP.relativeStackPosition = 1

UDP.srcport = Field.new("udp.srcport")
UDP.dstport = Field.new("udp.dstport")
UDP.length = Field.new("udp.length")
UDP.checksum = Field.new("udp.checksum")

--Policy validation functions
UDP.policyValidation = {
    sourcePort = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "KeepRange", "Zero"}),
    destinationPort = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "KeepRange", "Zero"}),
    length = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Recalculate"}),
    checksum = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero", "Recalculate"}),
    payload = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"KeepOriginal", "KeepAnonymized", "Discard"})
}

function UDP.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = UDP.relativeStackPosition
    UDP.relativeStackPosition = UDP.relativeStackPosition - 1

    --Shorthand to make life easier
    local policy = config.anonymizationPolicy.udp

    --Get fields
    local udpSrc = shanonHelpers.getRaw(tvb, UDP.srcport, relativeStackPosition)
    local udpDst = shanonHelpers.getRaw(tvb, UDP.dstport, relativeStackPosition)
    local udpLength = shanonHelpers.getRaw(tvb, UDP.length, relativeStackPosition)
    local udpChecksum = shanonHelpers.getRaw(tvb, UDP.checksum, relativeStackPosition)

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local udpSrcAnon
    local udpDstAnon
    local udpLengthAnon
    local udpChecksumAnon

    --Anonymize stuff here

    --Src port
    if policy.sourcePort == "Keep" then
        udpSrcAnon = udpSrc
    elseif policy.sourcePort == "KeepRange" then 
        udpSrcAnon = libAnonLua.get_port_range(udpSrc)
    else
        udpSrcAnon = ByteArray.new("0000"):raw()
    end
    
    --Dst port
    if policy.destinationPort == "Keep" then
        udpDstAnon = udpDst
    elseif policy.destinationPort == "KeepRange" then 
        udpDstAnon = libAnonLua.get_port_range(udpDst)
    else
        udpDstAnon = ByteArray.new("0000"):raw()
    end
    
    --Handling the payload
    if policy.payload == "KeepOriginal" then
        local udpPayloadLength = shanonHelpers.getValue(UDP.length, relativeStackPosition) - 8
        --Retrieve the original payload
        anonymizedFrame = shanonHelpers.getaBytesAfterField(tvb, UDP.checksum, relativeStackPosition, udpPayloadLength)
    elseif policy.payload == "KeepAnonymized" then 
        if anonymizedFrame == "" then 
            --If the anonymized frame isn't present, we generate a minimum payload OR a length-specific payload depending on the length option
            if policy.length == "Keep" then 
                local udpPayloadLength = shanonHelpers.getValue(UDP.length, relativeStackPosition) - 8
                anonymizedFrame = shanonHelpers.generateZeroPayload(udpPayloadLength)
            else 
                --Generate a minimum zero payload of 20 bytes
                anonymizedFrame = shanonHelpers.generateZeroPayload(20)
            end
        end
    else
        --Discard
        if policy.length == "Keep" then 
            local udpPayloadLength = shanonHelpers.getValue(UDP.length, relativeStackPosition) - 8
            anonymizedFrame = shanonHelpers.generateZeroPayload(udpPayloadLength)
        else 
            --Generate a minimum zero payload of 20 bytes
            anonymizedFrame = shanonHelpers.generateZeroPayload(20)
        end
    end

    --Handling the length
    if policy.length == "Keep" then 
        udpLengthAnon = udpLength
    else
        udpLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame, 2, 8)
    end

    --Handling the checksum
    if policy.checksum == "Keep" then 
        udpChecksumAnon = udpChecksum
    else 
        --If we're not keeping the checksum then we set it to 0 for either recalculation or the zero option
        udpChecksumAnon = ByteArray.new("0000"):raw()
    end    

    --Write to the anonymized frame here
    local udpDatagram = udpSrcAnon .. udpDstAnon .. udpLengthAnon .. udpChecksumAnon .. anonymizedFrame
    return udpDatagram
end

function UDP.validatePolicy(config)
    
    if config.anonymizationPolicy.udp == nil then 
        --If the policy doesn't exist, crash because it's missing
        shanonHelpers.crashMissingPolicy("UDP")
    else
        --Run every validator over the options in the policy
        for option, validator in pairs(UDP.policyValidation) do
            if not validator(config.anonymizationPolicy.udp[option]) then
                shanonHelpers.crashMissingPolicy("UDP", option)
            end
        end
    end
end

--Return the module table
return UDP