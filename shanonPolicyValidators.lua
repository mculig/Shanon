local policyValidators = {}

local shanonHelpers = require "shanonHelpers"

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
function policyValidators.validateSetValue(setValueString, range)
    local patternSetValue = "(SetValue_)%d+"

    --Check if the setValueString is nil
    if setValueString == nil then 
        return false
    end 

    --If the setValueString matches the pattern it passes
    if "" == string.gsub(setValueString, patternSetValue, "") then
        local setValueParameters, parameterCount = shanonHelpers.split(setValueString, "_")
        local numberString = setValueParameters[2]
        --Numerical value of SetValue value
        local numberValue = tonumber(numberString)

        local minimum = range[1]
        local maximum = range[2]

        if numberValue >= minimum and numberValue <= maximum then
            return true
        end
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
    local patternSubnet = "%d+%.%d+%.%d+%.%d+%/%d+"

    if subnet == nil then 
        return false
    end 

    if "" == string.gsub(subnet, patternSubnet, "") then
        return true
    end

    return false
end

--Verify an IPv6 subnet
--This isn't perfect and many mistakes may still make it through, but validating IPv6 is difficult
function policyValidators.verifyIPv6Subnet(subnet)
    local substrings, countSubstrings = shanonHelpers.split(subnet, "/")

    --We should get an IPv6 address and a number determining the amount of bits when splitting using / as a delimiter
    if countSubstrings~=2 then
        return false
    end

    --The IPv6 address will be the 1st substring
    local addr = substrings[1]

    --IPv6 address portion validation code adapted from example at: https://stackoverflow.com/a/45055709
    addr = addr:match("^([a-fA-F0-9:]+)$")
    if addr ~= nil and #addr > 1 then
        -- address part
        local nc, dc = 0, false      -- chunk count, double colon
        for chunk, colons in addr:gmatch("([^:]*)(:*)") do
            if nc > (dc and 7 or 8) then 
                -- max allowed chunks
                goto verifyIPv6AddressValid
            end    
            if #chunk > 0 and tonumber(chunk, 16) > 65535 then
                return false
            end
            if #colons > 0 then
                -- max consecutive colons allowed: 2
                if #colons > 2 then 
                    return false 
                end
                -- double colon shall appear only once
                if #colons == 2 and dc == true then 
                    return false 
                end
                if #colons == 2 and dc == false then 
                    dc = true 
                end
            end
            nc = nc + 1      
        end
        goto verifyIPv6AddressValid
    end

    --If we go here that means the address is valid
    ::verifyIPv6AddressValid::

    --The number will be the 2nd substring
    local bitBoundary = substrings[2]

    bitBoundary = tonumber(bitBoundary)

    if bitBoundary ~= nil then 
        if bitBoundary>=0 and bitBoundary<=128 then
            return true
        end
    end

    --If we reach here it's not a valid IPv6 address
    return false
end

--Validator that runs multiple validators on the values of a table with keys that also need validation
--If any single key is invalid, return false
function policyValidators.keyValidatedTableMultiValidatorFactory(keyValidationFunction, tableHasDefault, ...)
    local args = {...}
    return function(policyOption)
        --Need to check if the policy is nil
        if policyOption == nil then
            return false
        end
        -- Actual validation
        for key, policyRow in pairs(policyOption) do
            if next(policyRow) == nil then
                --An empty row isn't a valid configuration
                return false
            end
            --For every key
            if keyValidationFunction(key) or (tableHasDefault and key == "default") then
                for i, policyItem in ipairs(policyRow) do
                    --For every item in the policy
                    local matchesAtLeastOne = false
                    for j, validator in ipairs(args) do 
                        --For every validator
                        if type(validator) == "function" then 
                            --If the validator is a function, execute it
                            local result = validator(policyItem, args[j+1])
                            if result then 
                                --If at least one validator returns true then it's valid
                                matchesAtLeastOne = result
                                break
                            end
                        end
                    end
                    if not matchesAtLeastOne then
                        --If even one of the strings does not match even one validator then return false
                        shanonHelpers.writeLog(shanonHelpers.logWarn, "Validated configuration item \"" .. policyItem .. "\" did not meet validation criteria. See warnings below for the exact setting that produced this warning.")
                        return false
                    end
                end
            else
                --Wrong key
                shanonHelpers.writeLog(shanonHelpers.logWarn, "Invalid key value: \"" .. key .. "\" in configuration. See warnings below for the exact setting that produced this warning.")
                return false
            end
        end
        --If we reach here without returning false, the policy is valid
        return true
    end
end

return policyValidators