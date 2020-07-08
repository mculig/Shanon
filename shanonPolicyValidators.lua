local policyValidators = {}

--Verify that an option is one of the possible options
function policyValidators.isPossibleOption(policyOption, acceptableOptions)

    local i = 1

    --Check if the provided policyOption is nil
    if policyOption == nil then 
        return false
    end

    --Check if the provided policyOption is in the acceptableOptions
    while acceptableOptions[i] ~= nil do
        if policyOption == acceptableOptions[i] then
            return true
        end
        i = i + 1
    end

    return false
end

--Validate that the black market option values are correct
function policyValidators.validateBlackMarker(blackMarkerString)
    local patternMSB = "(BlackMarker_MSB_)%d+"
    local patternLSB = "(BlackMarker_LSB_)%d+"

    --Check if the blackMarkerString is nil
    if blackMarkerString == nil then 
        return false
    end

    --If the blackMarkerString matches either pattern it passes
    if "" == string.gsub(blackMarkerString, patternMSB, "") or "" == string.gsub(blackMarkerString, patternLSB, "") then 
        return true
    end

    return false
end

return policyValidators