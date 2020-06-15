--Json library
local dkjson = require "dkjson"

--LibAnonLua, our library
local libAnonLua = require "libAnonLua"

--Helper functions separated for readability
local shanonHelpers = require "shanonHelpers"

--Anonymization policy
--TODO: Parse a file with the policy
local anonymizationPolicy = nil

--Taps and fields for the various protocols being used

--Wireshark frame
local Tap_Frame = Listener.new("frame")
--Fields
local Field_frame_protocols = Field.new("frame.protocols")
local Field_frame_number = Field.new("frame.number")

-- Ethernet
local ethernet = require "protocols.ethernet"

--ARP
local arp = require "protocols.arp"

--IPv4
local ipv4 = require "protocols.ipv4"

--IPv6 
local ipv6 = require "protocols.ipv6"

--ICMP
local icmp = require "protocols.icmp"

--ICMPv6
local icmpv6 = require "protocols.icmpv6"

--NDP counts as ICMPv6 in the Wireshark

--UDP
local udp = require "protocols.udp"

--TCP
local tcp = require "protocols.tcp"

--TODO: Change filesystem file names based on config
--TODO: Verify success or failure of operations and crash script accordingly
--Create the filesystem we'll be writing to
local filesystemPath ="test_anon.pcapng"
libAnonLua.create_filesystem(filesystemPath)
libAnonLua.add_interface(filesystemPath, libAnonLua.LINKTYPE_ETHERNET)

--Function to tap into every frame
function Tap_Frame.packet(pinfo, tvb, tapinfo)
    --TODO: Remove temporary prints
    print "Frame \n"


    -- Frame info
    local frameNumber = Field_frame_number()

    local anonymizedFrame = "" --Create an empty anonymized frame
    local anonymizerOutput -- To temporarily hold the output of a particular anonymizer

    --Get the protocol list
    local protocolList, protocolCount = shanonHelpers.split(tostring(Field_frame_protocols()), ":")

    --Add counts to existing anonymizers
    --A protocol can appear multiple times
    --When fetching the individual protocol fields it is important to know which instance of the protocol this is in the chain
    --This is done by counting the number of times this appears and setting a relativeStackPosition
    --As the chain is parsed each time a protocol is encountered and processed this stack position is decremented
    ethernet.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "eth")
    arp.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "arp")
    ipv4.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "ip")
    ipv6.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "ipv6")
    icmp.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "icmp")
    icmpv6.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "icmpv6")
    udp.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "udp")
    tcp.relativeStackPosition = shanonHelpers.countOccurences(protocolList, protocolCount, "tcp")



    --TODO: Remove temporary prints
    print(Field_frame_protocols()) 

    
    --Current position in protocol stack
    local currentPosition = protocolCount

    while currentPosition ~= 0 do
        --Reset anonymizerOutput to empty string
        anonymizerOutput = ""
        if protocolList[currentPosition] == "eth" then
            anonymizerOutput  = ethernet.anonymize(tvb, protocolList, currentPosition, anonymizationPolicy) 
        elseif protocolList[currentPosition] == "ethertype" then
            --Nothing needs to be done for this. 
            --ethertype is a faux protocol that just serves to inform that Ethernet II with a type field is in use
        elseif protocolList[currentPosition] == "ip" then
            status, anonymizerOutput = pcall(ipv4.anonymize, tvb, protocolList, anonymizationPolicy)
            if status == false then
                --An error was thrown. anonymizerOutput has the error info
                shanonHelpers.writeLog(shanonHelpers.logError, "IPv4 anonymizer produced the following error: " .. anonymizerOutput)
                --Set the output to an empty string so nothing is added to the frame
                anonymizerOutput = ""
            end
        elseif protocolList[currentPosition] == "ipv6" then
            status, anonymizerOutput = pcall(ipv6.anonymize, tvb, protocolList, anonymizationPolicy)
            if status == false then
                --An error was thrown. anonymizerOutput has the error info
                shanonHelpers.writeLog(shanonHelpers.logError, "IPv6 anonymizer produced the following error: " .. anonymizerOutput)
                --Set the output to an empty string so nothing is added to the frame
                anonymizerOutput = ""
            end
        elseif protocolList[currentPosition] == "arp" then
            status, anonymizerOutput = pcall(arp.anonymize, tvb, protocolList, anonymizationPolicy)
            if status == false then
                --An error was thrown. anonymizerOutput has the error info
                shanonHelpers.writeLog(shanonHelpers.logError, "ARP anonymizer produced the following error: " .. anonymizerOutput)
                --Set the output to an empty string so nothing is added to the frame
                anonymizerOutput = ""
            end
        elseif protocolList[currentPosition] == "icmp" then
            status, anonymizerOutput = pcall(icmp.anonymize, tvb, protocolList, anonymizationPolicy)
            if status == false then
                --An error was thrown. anonymizerOutput has the error info
                shanonHelpers.writeLog(shanonHelpers.logError, "ICMP anonymizer produced the following error: " .. anonymizerOutput)
                --Set the output to an empty string so nothing is added to the frame
                anonymizerOutput = ""
            end
            --In the particular case of ICMP and ICMPv6 the anonymizedFrame should always be set to empty
            --This is because we will catch and parse the protocol headers and fields included as a 
            --partial header/data in the ICMP data as they show up in the list of protocols we get from Wireshark
            --But we don't want to anonymize partial headers to avoid issues 
            --Instead we're treating them as data in the ICMP/ICMPv6 anonymizer
            anonymizedFrame = ""
        elseif protocolList[currentPosition] == "icmpv6" then
            status, anonymizerOutput = pcall(icmpv6.anonymize, tvb, protocolList, anonymizationPolicy)
            if status == false then
                --An error was thrown. anonymizerOutput has the error info
                shanonHelpers.writeLog(shanonHelpers.logError, "ICMPv6 anonymizer produced the following error: " .. anonymizerOutput)
                --Set the output to an empty string so nothing is added to the frame
                anonymizerOutput = ""
            end
            --In the particular case of ICMP and ICMPv6 the anonymizedFrame should always be set to empty
            --This is because we will catch and parse the protocol headers and fields included as a 
            --partial header/data in the ICMP data as they show up in the list of protocols we get from Wireshark
            --But we don't want to anonymize partial headers to avoid issues 
            --Instead we're treating them as data in the ICMP/ICMPv6 anonymizer
            anonymizedFrame = ""
        elseif protocolList[currentPosition] == "tcp" then
            --TODO: Anonymizer
        elseif protocolList[currentPosition] == "udp" then
            status, anonymizerOutput = pcall(udp.anonymize, tvb, protocolList, anonymizationPolicy)
            if status == false then
                --An error was thrown. anonymizerOutput has the error info
                shanonHelpers.writeLog(shanonHelpers.logError, "UDP anonymizer produced the following error: " .. anonymizerOutput)
                --Set the output to an empty string so nothing is added to the frame
                anonymizerOutput = ""
            end
        else
            --If we encounter something unknown, we simply set the anonymized frame empty again
            anonymizedFrame = ""
            --An empty frame signals to anonymizer functions that higher layer protocols should be treated as data
        end

        --Add to front of anonymized frame
        anonymizedFrame = anonymizerOutput .. anonymizedFrame
        --Always decrement the current position
        currentPosition = currentPosition - 1; 
    end

    
    --At this point we will have parsed and anonymized all protocolsP
     --We can write the anonymized frame to the capture file
    if anonymizedFrame ~= "" then
        libAnonLua.write_packet(filesystemPath, anonymizedFrame, 0) --Optional third parameter: Timestamp
    else
        --If the frame is empty we don't write it. We log it.
        --TODO: Log this!
    end


end

function calculateChecksums()

end

function writeFrame()

end