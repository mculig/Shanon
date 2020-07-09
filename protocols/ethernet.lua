--Functions for Ethernet 

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"
local shanonPolicyValidators = require "shanonPolicyValidators"

--Module table
local Ethernet={}

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
Ethernet.relativeStackPosition = 1

--Ethernet Fields
Ethernet.dst = Field.new("eth.dst") --Destination address
Ethernet.src = Field.new("eth.src") --Source Address
Ethernet.type = Field.new("eth.type") -- Type
Ethernet.length = Field.new("eth.len") -- Length
--FCS is often not present and needs to be recalculated anyway

--The default anonymization policy for this protocol
Ethernet.defaultPolicy = {
    --Recalculate the fcs, apply a BlackMarker method to the address, recalculate the length based on payload length
    fcs = "Recalculate",
    address = "BlackMarker_MSB_24",
    length = "Recalculate"
}

--Policy validation functions for Ethernet policies
Ethernet.policyValidation = 
{
    fcs = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Recalculate", "Skip"}),
    address = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil),
    length = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Recalculate", "Keep"})
}

--A minimum Ethernet payload length
Ethernet.minimumPayloadLength = 46

--Is the anonymization policy valid. This check need only be done once
Ethernet.policyIsValid = false

function Ethernet.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = Ethernet.relativeStackPosition
    Ethernet.relativeStackPosition = Ethernet.relativeStackPosition - 1

    --If the policy is invalid (or on 1st run) we validate the policy
    if Ethernet.policyIsValid == false then 
        Ethernet.validatePolicy(config)
        Ethernet.policyIsValid = true
    end

    --Create local policy simply to avoid having to type config.anonymizationPolicy.ethernet all the time
    local policy = config.anonymizationPolicy.ethernet

    --Get fields
    local ethDst = shanonHelpers.getRaw(tvb, Ethernet.dst, relativeStackPosition)
    local ethSrc = shanonHelpers.getRaw(tvb, Ethernet.src, relativeStackPosition)
    local ethType = nil
    local ethLength = nil

    if protocolList[currentPosition+1]=="ethertype" then
        ethType = shanonHelpers.getRaw(tvb, Ethernet.type, relativeStackPosition)
    else
        ethLength = shanonHelpers.getRaw(tvb, Ethernet.length, relativeStackPosition)
    end

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local ethDstAnon
    local ethSrcAnon
    local ethTypeLengthAnon 

    --Check if a payload is empty and use a minimum zero payload if so
    if anonymizedFrame == "" then 
        anonymizedFrame = shanonHelpers.generateZeroPayload(Ethernet.minimumPayloadLength)
    end

    --Anonymize stuff here
    if policy.address == "Keep" then 
        ethDstAnon = ethDst
        ethSrcAnon = ethSrc
    else
        local blackMarkerDirection, blackMarkerLength = shanonHelpers.getBlackMarkerValues(policy.address)
        ethDstAnon = libAnonLua.black_marker(ethDst, blackMarkerLength, blackMarkerDirection)
        ethSrcAnon = libAnonLua.black_marker(ethSrc, blackMarkerLength, blackMarkerDirection)
    end
    
    --If the ethertype is present
    if ethType ~= nil then 
        --Not anonymizing type
        ethTypeLengthAnon = ethType 
    end

    --If the ethernet length is present
    if ethLength ~=nil then 
        if policy.length == "Recalculate" then 
            ethTypeLengthAnon = shanonHelpers.getLengthAsBytes(anonymizedFrame:len(), 2)
        else 
            ethTypeLengthAnon = ethLength
        end 
    end

    local ethernetFrame = ethDstAnon .. ethSrcAnon .. ethTypeLengthAnon .. anonymizedFrame

    if policy.fcs == "Recalculate" then 
        ethernetFrame = select(2, libAnonLua.calculate_eth_fcs(ethernetFrame))
    end

    --Return the anonymization result
    return ethernetFrame
end

function Ethernet.validatePolicy(config)

    --Check if the config has an anonymizationPolicy
    shanonPolicyValidators.verifyPolicyExists(config)

    --If there is no policy for Ethernet, copy the default policy over
    --Otherwise check if each individual policy value is valid
    if config.anonymizationPolicy.ethernet == nil then 
        shanonHelpers.warnMissingPolicy("Ethernet")
        config.anonymizationPolicy.ethernet = Ethernet.defaultPolicy
    else
        if not Ethernet.policyValidation.fcs(config.anonymizationPolicy.ethernet.fcs) then
            shanonHelpers.warnUsingDefaultOption("Ethernet", "FCS", Ethernet.defaultPolicy.fcs)
            config.anonymizationPolicy.ethernet.fcs = Ethernet.defaultPolicy.fcs 
        end
        if not Ethernet.policyValidation.address(config.anonymizationPolicy.ethernet.address) then
            shanonHelpers.warnUsingDefaultOption("Ethernet", "address", Ethernet.defaultPolicy.address)
            config.anonymizationPolicy.ethernet.address = Ethernet.defaultPolicy.address
        end
        if not Ethernet.policyValidation.length(config.anonymizationPolicy.ethernet.length) then
            shanonHelpers.warnUsingDefaultOption("Ethernet", "length", Ethernet.defaultPolicy.length)
            config.anonymizationPolicy.ethernet.length = Ethernet.defaultPolicy.length
        end
    end

end

--Return the module table
return EthernetwarnUsingDefaultOption