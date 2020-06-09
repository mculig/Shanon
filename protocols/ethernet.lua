--Functions for Ethernet 

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

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

function Ethernet.anonymize(tvb, protocolList, currentPosition, anonymizationPolicy)

    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = Ethernet.relativeStackPosition
    Ethernet.relativeStackPosition = Ethernet.relativeStackPosition - 1

    --Get fields
    local ethDst = shanonHelpers.getRaw(tvb, Ethernet.dst, relativeStackPosition)
    local ethSrc = shanonHelpers.getRaw(tvb, Ethernet.src, relativeStackPosition)
    local ethTypeLength

    if protocolList[currentPosition+1]=="ethertype" then
        ethTypeLength = shanonHelpers.getRaw(tvb, Ethernet.type, relativeStackPosition)
    else
        ethTypeLength = shanonHelpers.getRaw(tvb, Ethernet.length, relativeStackPosition)
    end

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local ethDstAnon
    local ethSrcAnon
    local ethTypeLengthAnon

    --Anonymize stuff here
    ethDstAnon = ethDst
    ethSrcAnon = ethSrc
    ethTypeLengthAnon = ethTypeLength

    --Return the anonymization result
    return ethDstAnon .. ethSrcAnon .. ethTypeLengthAnon 
end

--Return the module table
return Ethernet