--Functions for Ethernet 

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local Ethernet={}

--Ethernet Fields
Ethernet.dst = Field.new("eth.dst") --Destination address
Ethernet.src = Field.new("eth.src") --Source Address
Ethernet.type = Field.new("eth.type") -- Type
Ethernet.length = Field.new("eth.len") -- Length
--FCS is often not present and needs to be recalculated anyway

function Ethernet.anonymize(tvb, protocolList, currentPosition, anonymizationPolicy)
    --Get fields
    local ethDst = shanonHelpers.getRaw(tvb, Ethernet.dst())
    local ethSrc = shanonHelpers.getRaw(tvb, Ethernet.src())
    local ethTypeLength

    if protocolList[currentPosition+1]=="ethertype" then
        ethTypeLength = shanonHelpers.getRaw(tvb, Ethernet.type())
    else
        ethTypeLength = shanonHelpers.getRaw(tvb, Ethernet.length())
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