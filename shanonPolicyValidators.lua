local policyValidators = {}

--The main validation function 
--This function will accept multiple functions and parameters to test inputs
--and returning a function that can be called with a provided policy option to verify this option meets
--one or all of the criteria provided
--Format: function, nArgs, Arg1...Argn, function2...
--Example: validateMultipleRules(false, function1, 3, arg1, arg2, arg3)
function policyValidators.policyValidatorFactory(mustMatchAll, ...)
    local args = {...}
    return function(policyOption)
        for i, v in ipairs(args) do
            if type(v) == "function" then
                local result = v(policyOption, args[i+1])
                --If we must match all policies, return false upon a single false result.
                --If we just need to match one, return true for the first match
                if mustMatchAll then 
                    if result == false then 
                        return false
                    end
                else
                    if result == true then 
                        return true
                    end
                end
            end
        end
        --If we haven't already returned, then the result will be true for mustMatchAll
        --since a single false result would have returned earlier
        --or false if mustMatchAll is false, since a single true result would have returned earlier
        if mustMatchAll then 
            return true
        else
            return false 
        end
    end
end

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

--Validate the SetValue policy option
function policyValidators.validateSetValue(setValueString)
    local patternSetValue = "(SetValue_)%d+"

    --Check if the setValueString is nil
    if setValueString == nil then 
        return false
    end 

    --If the setValueString matches the pattern it passes
    if "" == string.gsub(setValueString, patternSetValue, "") then
        return true
    end

    return false
end

--Verify that a policy exists in the config and create an empty policy if not
function policyValidators.verifyPolicyExists(config)
    if config.anonymizationPolicy == nil then 
        config.anonymizationPolicy = {}
        shanonHelpers.writeLog(shanonHelpers.logWarn, "Anonymization policy not found. Default values will be used when anonymizing packets!")
    end
end

--Verify an IPv4 subnet
function policyValidators.verifyIPv4Subnet(subnet)
    local patternSubnet = "[0-255]%.[0-255]%.[0-255]%.[0-255]%/[0-32]"

    if subnet == nil then 
        return false
    end 

    if "" == string.gsub(subnet, patternSubnet, "") then
        return true
    end

    return false
end

return policyValidators