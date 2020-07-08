--Required. Create Config variable. Can be named anything
local Config = {}

--Anonymization output file name including extension. Regardless what is written here the file will always be a pcapng file.
--If this is omitted a default output file name will be used
Config.outputFile = "shanon_output.pcapng"

--The anonymization policy. This policy is made up of anonymization rules for the individual protocols Shanon supports
--If a protocol is omitted a default policy will be used for that protocol
Config.anonymizationPolicy = {}

--The anonymization policy for the frame as written in the pcapng filesystem
--This policy only specifies how Shanon should deal with the timestamps of captured frames

Config.anonymizationPolicy.frame = {
    --Options: 
    --Absolute: The absolute time when the packet was captured. 
    --Relative: The relative time when the packet was captured compared to the start of the capture
    timestamp = "Relative"
}

Config.anonymizationPolicy.ethernet = {
    --Frame check sequence
    --Options:
    --Skip: Do not include a FCS with the captured frame
    --Recalculate: Calculate a new, correct FCS
    fcs = "Recalculate",
    --MAC addresses
    --Options:
    --Keep: Addresses are left unchanged
    --BlackMarker: Use a BlackMarker. The syntax is as follows: BlackMarker_Direction_CountBits. 
    --Example: BlackMarker_MSB_24 would apply the method to the most significant 24 bits
    -- BlackMarker_LSB_24 would apply the method to the least significant 24 bits
    address = "BlackMarker_MSB_24",
    --Payload length
    --Options:
    --Recalculate: Calculate a new, correct length, based on the anonymized payload
    --Keep: Keep the original length
    length = "Recalculate"
}


--Required. Return the variable created at the start. This must be the last line
return Config