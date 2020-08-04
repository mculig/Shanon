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
UDP.streamIndex = Field.new("udp.stream")

--Policy validation functions
UDP.policyValidation = {
    sourcePort = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "KeepRange", "Zero"}),
    destinationPort = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "KeepRange", "Zero"}),
    checksum = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero", "Recalculate"}),
    payload = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"ZeroMinimumLength", "ZeroOriginalLength", "Keep","Anonymized1","Anonymized2"}),
    metaStreamIndex = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Preserve", "Discard"})
}

function UDP.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = UDP.relativeStackPosition
    UDP.relativeStackPosition = UDP.relativeStackPosition - 1

    --Shorthand to make life easier
    local policy = config.anonymizationPolicy.udp

    --The comment for this m,essage. Used to preserve metadata in the form of comments on packets
    local comment = ""
    
    --If a frame has UDP in it we will preserve the UDP stream index as a comment to enable analysis despite anonymization being destructive
    if policy.metaStreamIndex == "Preserve" then 
        comment = comment .. "original_stream_index = " .. shanonHelpers.getValue(UDP.streamIndex, relativeStackPosition)
    end

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
    
    --Length is either recalculated or not, depending on the payload
    --Payload options are processed here

    if policy.payload == "ZeroMinimumLength" then 
        anonymizedFrame = shanonHelpers.generateZeroPayload(20)
        udpLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame, 2, 8)
    elseif policy.payload == "ZeroOriginalLength" then 
        local udpPayloadLength = shanonHelpers.getValue(UDP.length, relativeStackPosition) - 8
        anonymizedFrame = shanonHelpers.generateZeroPayload(udpPayloadLength)
        udpLengthAnon = udpLength
    elseif policy.payload == "Keep" then 
        local udpPayloadLength = shanonHelpers.getValue(UDP.length, relativeStackPosition) - 8
        anonymizedFrame = shanonHelpers.getaBytesAfterField(tvb, UDP.checksum, relativeStackPosition, udpPayloadLength)
        udpLengthAnon = udpLength
    elseif policy.payload == "Anonymized1" then 
        if anonymizedFrame ~= "" then 
            --If the anonymized frame is present then a higher layer anonymizer returned something
            --We use that something and just recalculate the length
            udpLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame, 2, 8)
        else 
            --Same as ZeroMinimumLength
            anonymizedFrame = shanonHelpers.generateZeroPayload(20)
            udpLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame, 2, 8)
        end
    elseif policy.payload == "Anonymized2" then 
        if anonymizedFrame ~= "" then 
            --If the anonymized frame is present then a higher layer anonymizer returned something
            --We use that something and just recalculate the length
            udpLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame, 2, 8)
        else 
            --Same as ZeroOriginalLength
            local udpPayloadLength = shanonHelpers.getValue(UDP.length, relativeStackPosition) - 8
            anonymizedFrame = shanonHelpers.generateZeroPayload(udpPayloadLength)
            udpLengthAnon = udpLength
        end
    end

    --Handling the checksum
    --The checksum is recalculated by the IPv4 or IPv6 anonymizer
    if policy.checksum == "Keep" then 
        udpChecksumAnon = udpChecksum
    else 
        --If we're not keeping the checksum then we set it to 0 for either recalculation or the zero option
        udpChecksumAnon = ByteArray.new("0000"):raw()
    end    

    --Write to the anonymized frame here
    local udpDatagram = udpSrcAnon .. udpDstAnon .. udpLengthAnon .. udpChecksumAnon .. anonymizedFrame
    return udpDatagram, comment
end

function UDP.validatePolicy(config)
    
    --Check if the config has an anonymizationPolicy
    shanonPolicyValidators.verifyPolicyExists(config)

    if config.anonymizationPolicy.udp == nil then 
        --If the policy doesn't exist, crash because it's missing
        shanonHelpers.crashMissingPolicy("UDP")
    else
        --Run every validator over the options in the policy
        for option, validator in pairs(UDP.policyValidation) do
            if not validator(config.anonymizationPolicy.udp[option]) then
                shanonHelpers.crashMissingOption("UDP", option)
            end
        end
    end
end

--Return the module table
return UDP