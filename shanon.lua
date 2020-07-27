--LibAnonLua, our library
local libAnonLua = require "libAnonLua"

--Helper functions separated for readability
local shanonHelpers = require "shanonHelpers"

--The required version of libAnonLua
local requiredLibAnonLuaVersion = 3

--Verify the libAnonLua version before doing much else
if libAnonLua.version ~= requiredLibAnonLuaVersion then
        shanonHelpers.crashWithError("The current version of Shanon requires libAnonLua version " 
        .. requiredLibAnonLuaVersion .. " but found version " .. libAnonLua.version)
end 

--Load config file
--The config file will also be a Lua file
--This allows for comments and documentation in the config
local configStatus, config = pcall(require, "config.config")
if configStatus == false then 
    shanonHelpers.crashWithError(
        "Error loading config file. Loading produced the following error: " .. config, 
        "Error loading config file. See log for details.")
end


--Anonymization policy
--TODO: Remove this. Policy is part of the config now
local anonymizationPolicy = nil

--Taps and fields for the various protocols being used

--Wireshark frame
local Tap_Frame = Listener.new("frame")
--Fields
local Field_frame_protocols = Field.new("frame.protocols")
local Field_frame_number = Field.new("frame.number")

--Protocols we anonymize
local protocols = {
    ethernet = require "protocols.ethernet",
    arp = require "protocols.arp",
    ipv4 = require "protocols.ipv4",
    ipv6 = require "protocols.ipv6",
    icmp = require "protocols.icmp",
    icmpv6 = require "protocols.icmpv6",
    udp = require "protocols.udp",
    tcp = require "protocols.tcp"
}

--Get the output file path from the config file
local filesystemPath = shanonHelpers.configGetOutputPath(config)
libAnonLua.create_filesystem(filesystemPath)
libAnonLua.add_interface(filesystemPath, libAnonLua.LINKTYPE_ETHERNET)

--Get the CryptoPAN key file
local cryptoPANKeyFile = shanonHelpers.configGetCryptoPANKeyFile(config)
local cryptoPANStatus = libAnonLua.init_cryptoPAN(cryptoPANKeyFile)
if cryptoPANStatus == -1 then 
    shanonHelpers.crashWithError("Failed to initialize CryptoPAN!")
end

--Validate all the anonymization policies here
for protocolName, protocol in pairs(protocols) do
    protocol.validatePolicy(config)
    print("Validated " .. protocolName)
end

--Function to tap into every frame
function Tap_Frame.packet(pinfo, tvb, tapinfo)
    -- Frame info
    local frameNumber = Field_frame_number()

    local status --Status for pcall 
    local anonymizedFrame = "" --Create an empty anonymized frame

    --Get the protocol list
    local protocolList, protocolCount = shanonHelpers.split(tostring(Field_frame_protocols()), ":")

    --Add counts to existing anonymizers
    --A protocol can appear multiple times
    --When fetching the individual protocol fields it is important to know which instance of the protocol this is in the chain
    --This is done by counting the number of times this appears and setting a relativeStackPosition
    --As the chain is parsed each time a protocol is encountered and processed this stack position is decremented
    for protocolName, protocol in pairs(protocols) do 
        protocol.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, protocol.filterName)
    end

    --TODO: Remove temporary prints
    print(Field_frame_protocols()) 
    
    --Current position in protocol stack
    local currentPosition = protocolCount

    while currentPosition ~= 0 do

        --Check if protocol is one we know how to deal with
        local protocolMatchFound = false

        for protocolName, protocol in pairs(protocols) do
            if protocolList[currentPosition] == protocol.filterName then
                --This is a protocol we know how to deal with
                protocolMatchFound = true
                status, output = pcall(protocol.anonymize, tvb, protocolList, currentPosition, anonymizedFrame, config)
                if status == false then 
                    --Clear the anonymized frame so erroneous output isn't accidentally preserved
                    anonymizedFrame = ""
                    --Crash with an error
                    shanonHelpers.crashWithError(
                        "Error in frame: " .. frameNumber.value .. 
                        ". Anonymizer for protocol: \"" .. protocolName .. "\" encountered an error. Check log for details.", 
                        "Error in frame: " .. frameNumber.value .. ". Anonymizer for protocol: \"" .. protocolName .. 
                        "\" encountered the following error: " .. output)
                else
                    --If everything went smoothly, set the anonymized frame to our anonymizer's output
                    anonymizedFrame = output
                end
                --End the loop here
                break
            elseif protocol.fauxProtocols ~= nil then 
                --If the protocol we're testing has a function to determine if a protocol is a faux protocol
                --Such as the "ethertype" protocol that is simply a marker for Ethernet using a type field
                --Then we run it to see if our protocol matches and if it does we count it as processed
                if protocol.fauxProtocols(protocolList[currentPosition]) then 
                    protocolMatchFound = true
                    break
                end
                
            end
        end
        --If we do not find a matching protocol, we log it and set the frame to empty here so the next protocol knows
        --to treat the lower layer stuff as data
        if not protocolMatchFound then 
            --TODO: This is a lot of log data. Provide an option to mute it if it's not of interest to the user
            shanonHelpers.writeLog(shanonHelpers.logInfo, "Unhandled protocol: \"" .. protocolList[currentPosition] .. "\" encountered at position: " 
            .. currentPosition .. " in protocol chain in frame " .. frameNumber.value .. 
            " This protocol will be treated as data by lower layer protocols and will be anonymized as data.")
            --If we encounter something unknown, we simply set the anonymized frame empty again
            anonymizedFrame = ""
            --An empty frame signals to anonymizer functions that higher layer protocols should be treated as data
        end

        --Always decrement the current position
        currentPosition = currentPosition - 1; 
    end

    
    --At this point we will have parsed and anonymized all protocolsP
     --We can write the anonymized frame to the capture file
    writePacket(pinfo, anonymizedFrame, frameNumber)
end

function writePacket(pinfo, anonymizedFrame, frameNumber)

    --Timestamp default value is relative
    local timestampValue = pinfo.rel_ts

    if config.anonymizationPolicy ~= nil and config.anonymizationPolicy.frame ~= nil and config.anonymizationPolicy.frame.timestamp ~= nil then
        if config.anonymizationPolicy.frame.timestamp == "Absolute" then
            timestampValue = pinfo.abs_ts
        elseif config.anonymizationPolicy.frame.timestamp == "Relative" then
            timestampValue = pinfo.rel_ts
        end 
    end

    --Write frame
    if anonymizedFrame ~= "" then
        libAnonLua.write_packet(filesystemPath, anonymizedFrame, 0, timestampValue)
    else
        --If the frame is empty we don't write it. We log it.
        shanonHelpers.writeLog(shanonHelpers.logError, "Error in frame: " .. frameNumber.value .. ". " .. "No data to write to output file. This may happen if there was another error or if the lowest layer protocol in this frame could not be processed.")
    end
end