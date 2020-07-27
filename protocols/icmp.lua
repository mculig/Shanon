--Functions for ICMP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"
local shanonPolicyValidators = require "shanonPolicyValidators"
local ipv4 = require "protocols.ipv4"

--Module table
local ICMP={}

--The filter name is used when looking for instances of this protocol
ICMP.filterName = "icmp"


--Relative stack position is used to determine which of many possible instances of this protocol is being processed
ICMP.relativeStackPosition = 1

ICMP.type = Field.new("icmp.type")
ICMP.code = Field.new("icmp.code")
ICMP.checksum = Field.new("icmp.checksum")
--These two fields show up in Echo, Echo Reply, Timestamp and Timestamp Reply
ICMP.identifier = Field.new("icmp.ident")
ICMP.sequenceNumber = Field.new("icmp.seq")
--This shows up in redirect
ICMP.redirectGateway = Field.new("icmp.redir_gw")
--This shows up in Parameter Problem
ICMP.pointer = Field.new("icmp.pointer")
--These show up in Timestamp and Timestamp Reply
ICMP.originateTimestamp = Field.new("icmp.originate_timestamp")
ICMP.receiveTimestamp = Field.new("icmp.receive_timestamp")
ICMP.transmitTimestamp = Field.new("icmp.transmit_timestamp")


ICMP.policyValidation = {
    checksum = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Recalculate"}),
    id = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    sequenceNumber = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    ppPointer = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep", "Zero"}),
    timestamp = shanonPolicyValidators.policyValidatorFactory(false, shanonPolicyValidators.isPossibleOption, {"Keep"}, shanonPolicyValidators.validateBlackMarker, nil)
}

function ICMP.anonymize(tvb, protocolList, currentPosition, anonymizedFrame, config)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = ICMP.relativeStackPosition
    ICMP.relativeStackPosition = ICMP.relativeStackPosition - 1

    --Get fields
    local icmpType = shanonHelpers.getRaw(tvb, ICMP.type, relativeStackPosition)
    local icmpCode = shanonHelpers.getRaw(tvb, ICMP.code, relativeStackPosition)
    local icmpChecksum = shanonHelpers.getRaw(tvb, ICMP.checksum, relativeStackPosition)

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local icmpTypeAnon
    local icmpCodeAnon
    local icmpChecksumAnon

    --Anonymize stuff here

    local policy = config.anonymizationPolicy.icmp

    --Nothing is done to the Type and Code of ICMP messages
    icmpTypeAnon = icmpType
    icmpCodeAnon = icmpCode
    --The checksum is recalculated later
    icmpChecksumAnon = icmpChecksum

    --Add anonymized header fields to ICMP message
    local icmpMessage = icmpTypeAnon .. icmpCodeAnon .. icmpChecksumAnon

    --Since different ICMP message types may or may not have certain fields
    --these fields will not have the same relative stack position as the other ICMP header fields
    --For example an ICMP Echo Identifier from an ICMP Echo that is contained within an ICMP Destination Unreachable message
    --would have a position of 1 even though the ICMP Echo message has a position of 2. 
    --Thus these values need to be retrieved not by using the index of the ICMP message itself but by retrieving that value which is within
    --the area of the TVB where the ICMP header currently being processed is

    --Start of ICMP message
    local icmpTypes = { ICMP.type() }
    local icmpStart = icmpTypes[relativeStackPosition].offset

    --End of ICMP message
    local icmpEnd
    local icmpNextType = icmpTypes[relativeStackPosition + 1]
    if icmpNextType ~=nil then
        --If there is a next ICMP message then our upper limit is the next message
        icmpEnd = icmpNextType.offset
    else
        --Otherwise it might as well be the end of the buffer
        icmpEnd = tvb:len()
    end

    --The rest is handled differently for different ICMP types
    local tmpType = ICMP.type().value
    if tmpType == 0 or tmpType == 8 then
        --Echo and Echo Reply
        --Get fields
        local icmpId = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.identifier, icmpStart, icmpEnd)
        local icmpSeq = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.sequenceNumber, icmpStart, icmpEnd)
        local icmpData = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMP.sequenceNumber,  icmpStart, icmpEnd)

        --Anonymized fields
        local icmpIdAnon
        local icmpSeqAnon
        local icmpDataAnon

        --Anonymize fields 

        --Id and sequence number
        if policy.id == "Keep" then 
            icmpIdAnon = icmpId
        else 
            icmpIdAnon = ByteArray.new("0000"):raw()
        end

        if policy.sequenceNumber == "Keep" then 
            icmpSeqAnon = icmpSeq
        else 
            icmpSeqAnon = ByteArray.new("0000"):raw()
        end
        
        --Data payload       

        if anonymizedFrame == "" then 
            --If we got nothing, create an empty data frame of length equal to ICMP data
            icmpDataAnon = shanonHelpers.generateZeroPayload(icmpData:len())
        else 
            icmoDataAnon = anonymizedFrame
        end

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpIdAnon .. icmpSeqAnon .. icmpDataAnon

    elseif tmpType == 3 then
        --Destination unreachable
        --Get fields
        --4 unused bytes past the checksum are grabbed from the buffer.
        --This method is used instead of using Field.new("icmp.unused") because there may be used for the unused field
        --but these uses aren't covered by this version of Shanon
        --The ICMP checksum is always present so no need to account for it maybe not being here
        local tmpChecksum = { ICMP.checksum() }
        local offset = tmpChecksum[relativeStackPosition].offset+tmpChecksum[relativeStackPosition].len
        local icmpUnused = tvb:range(offset, 4):bytes():raw()
        --Add 4 to offset to go past the unused bytes and capture just data
        local offset = offset + 4
        local icmpData = shanonHelpers.getRestFromOffset(tvb, offset)

        --Anonymized fields
        local icmpUnusedAnon
        local icmpDataAnon

        --Anonymize fields
        
        --Unused field, set bytes to 0
        icmpUnusedAnon = ByteArray.new("00000000"):raw()

        --Data payload   
        if anonymizedFrame == "" then 
            --If we got nothing, create an empty data frame of length equal to ICMP data
            icmpDataAnon = shanonHelpers.generateZeroPayload(icmpData:len())
        else 
            icmoDataAnon = anonymizedFrame
        end

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpUnusedAnon .. icmpDataAnon

    elseif tmpType == 5 then
        --Redirect
        --Get field
        local icmpRedirectGateway = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.redirectGateway,  icmpStart, icmpEnd)
        local icmpData = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMP.redirectGateway,  icmpStart, icmpEnd)

        --Anonymized fields
        local icmpRedirectGatewayAnon 
        local icmpDataAnon

        --Anonymize fields

        --Redirect gateway. For this we use the IPv4 rules

        local ipv4Policy
        
        --Test if our redirect gateway is in any of the subnets with its own policy
        if config.anonymizationPolicy.ipv4.subnets ~= nil then 
            for subnet, subnetPolicy in pairs(config.anonymizationPolicy.ipv4.subnets) do
                if libAnonLua.ip_in_subnet(icmpRedirectGateway, subnet) then 
                    ipv4Policy = subnetPolicy
                    break
                end
            end
        end

        --If we didn't find a specific policy, use the default
        if ipv4Policy == nil then 
            ipv4Policy = config.anonymizationPolicy.ipv4.default
        end     

        --Apply the correct anonymization to the gateway
        for subnet, anonymizationMethods in pairs(ipv4Policy.address) do 
            if subnet == "default" then 
                --Skip default here. If neither address is in any of the subnets then we'll default later
            else
                if libAnonLua.ip_in_subnet(icmpRedirectGateway, subnet) then 
                    icmpRedirectGatewayAnon = ipv4.applyAnonymizationMethods(icmpRedirectGateway, anonymizationMethods)
                    break;
                end
            end
        end

        --If we didn't find a matching subnet in the last step this will be nil
        if icmpRedirectGatewayAnon == nil then 
            icmpRedirectGatewayAnon = ipv4.applyAnonymizationMethods(icmpRedirectGateway, ipv4Policy.address.default)
        end

        --Data payload

        if anonymizedFrame == "" then 
            --If we got nothing, create an empty data frame of length equal to ICMP data
            icmpDataAnon = shanonHelpers.generateZeroPayload(icmpData:len())
        else 
            icmoDataAnon = anonymizedFrame
        end

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpRedirectGatewayAnon .. icmpDataAnon
    elseif tmpType == 12 then
        --Parameter problem 
        --Get fields
        local icmpPointer = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.pointer, icmpStart, icmpEnd)
        -- 3 Unused bytes after the pointer. 
        local icmpUnused = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMP.pointer, icmpStart, icmpEnd, 3)
        -- Data starts 4 bytes away from pointer offset. 
        local icmpData = shanonHelpers.getBytesAfterOnlyOneWithinBoundaries(tvb, ICMP.pointer, icmpStart, icmpEnd):sub(4)

        --Anonymized fields
        local icmpPointerAnon
        local icmpUnusedAnon
        local icmpDataAnon 

        --Anonymize fields

        if policy.ppPointer == "Keep" then 
            icmpPointerAnon = icmpPointer
        else 
            icmpPointerAnon = ByteArray.new("00"):raw()
        end

        icmpUnusedAnon = ByteArray.new("000000"):raw()

        --Data payload

        if anonymizedFrame == "" then 
            --If we got nothing, create an empty data frame of length equal to ICMP data
            icmpDataAnon = shanonHelpers.generateZeroPayload(icmpData:len())
        else 
            icmoDataAnon = anonymizedFrame
        end

        --Add anonymized fields to ICMP message
        icmpMessage = icmpMessage .. icmpPointerAnon .. icmpUnusedAnon .. icmpDataAnon

    elseif tmpType == 13 or tmpType == 14 then
        --Timestamp and timestamp reply
        --Get fields
        --The icmpIdentifier is interesting because Wireshark has 2 fields of this type for timestamps. The fields seem to be Little Endian and Big Endian representations
        --We'll expect 2, so an error will be thrown if there are more, then grab the 1st one as they should contain the same value
        local icmpIdentifier = select(2, shanonHelpers.getAllWithinBoundariesRaw(tvb, ICMP.identifier, icmpStart, icmpEnd, 2))
        icmpIdentifier = icmpIdentifier[1] 
        local icmpSeq = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.sequenceNumber, icmpStart, icmpEnd)
        local icmpOriginateTimestamp = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.originateTimestamp, icmpStart, icmpEnd)
        local icmpReceiveTimestamp = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.receiveTimestamp, icmpStart, icmpEnd)
        local icmpTransmitTimestamp = shanonHelpers.getOnlyOneWithinBoundariesRaw(tvb, ICMP.transmitTimestamp, icmpStart, icmpEnd)

        --Anonymized fields
        local icmpIdentifierAnon
        local icmpSeqAnon
        local icmpOriginateTimestampAnon
        local icmpReceiveTimestampAnon
        local icmpTransmitTimestampAnon

        --Anonymize fields

        if policy.id == "Keep" then 
            icmpIdentifierAnon = icmpIdentifier
        else 
            icmpIdentifierAnon = ByteArray.new("0000"):raw()
        end

        if policy.sequenceNumber == "Keep" then 
            icmpSeqAnon = icmpSeq
        else 
            icmpSeqAnon = ByteArray.new("0000"):raw()
        end

        if policy.timestamp == "Keep" then 
            icmpOriginateTimestampAnon = icmpOriginateTimestamp
            icmpReceiveTimestampAnon = icmpReceiveTimestamp
            icmpTransmitTimestampAnon = icmpTransmitTimestamp
        else
            local blackMarkerDirection, blackMarkerLength = shanonHelpers.getBlackMarkerValues(policy.timestamp)
            icmpOriginateTimestampAnon = libAnonLua.black_marker(icmpOriginateTimestamp, blackMarkerLength, blackMarkerDirection)
            icmpReceiveTimestampAnon = libAnonLua.black_marker(icmpReceiveTimestamp, blackMarkerLength, blackMarkerDirection)
            icmpTransmitTimestampAnon = libAnonLua.black_marker(icmpTransmitTimestamp, blackMarkerLength, blackMarkerDirection)
        end

        --Add anonymized fields to icmp message
        icmpMessage = icmpMessage .. icmpIdentifierAnon .. icmpSeqAnon .. icmpOriginateTimestampAnon
        icmpMessage = icmpMessage .. icmpReceiveTimestampAnon .. icmpTransmitTimestampAnon
    else
        --Handle other messages
        --Get data
        local icmpData = shanonHelpers.getRest(tvb, ICMP.checksum, relativeStackPosition)

        --Anonymized fields
        local icmpDataAnon

        --Anonymize fields
        icmpDataAnon = icmpData

        --Add anonymized fields to icmp message
        icmpMessage = icmpMessage .. icmpDataAnon
    end

    if policy.checksum == "Keep" then 
        --Do nothing, we already inserted the old checksum
    else 
        local checksum
        checksum, icmpMessage = libAnonLua.calculate_icmp_checksum(icmpMessage)
    end

    --Return the anonymization result
    return icmpMessage
end

--Validator for ICMP anonymization policy
function ICMP.validatePolicy(config)
    --Check if the config has an anonymizationPolicy
    shanonPolicyValidators.verifyPolicyExists(config)

    --Verify the policy exists and its contents
    if config.anonymizationPolicy.icmp == nil then
        shanonHelpers.crashMissingPolicy("ICMP")
    else
        for option, validator in pairs(ICMP.policyValidation) do
            if not validator(config.anonymizationPolicy.icmp[option]) then
                shanonHelpers.crashMissingOption("ICMP", option)
            end
        end
    end
end

--Return the module table
return ICMP