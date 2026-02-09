; Edit-friendly! 
; Feel free to edit the settings :)


%ifndef __BEHAVIOUR_CONFIG_INC_
%define __BEHAVIOUR_CONFIG_INC__

section .rodata:

    ; =======================================================================
    ;                       EDITABLE SECTION START
    ; =======================================================================

    cmd_Spreading_factor        db "AT+PARAMETER=8,7,1,8", 13, 10               ; Paramater
    cmd_Spreading_factor_len    equ $ - cmd_Spreading_factor

    cmd_Network_ID              db "AT+NETWORKID=18", 13, 10                    ; Network ID
    cmd_Network_ID_len          equ $ - cmd_Network_ID

    cmd_Receive                 db "AT+MODE=0", 13, 10
    cmd_Receive_len             equ $ - cmd_Receive

    cmd_Band                    db "AT+BAND="
    cmd_Band_len                equ $ - cmd_Band

    cmd_Output_power            db "AT+CRFOP=20", 13, 10                        ; Output Power
    cmd_Output_power_len        equ $ - cmd_Output_power

    cmd_Send                    db "AT+SEND="
    cmd_Send_len                equ $ - cmd_Send

    cmd_Address_R               db "AT+ADDRESS=7775", 13, 10                    ; Receiver Address
    cmd_Address_R_len           equ $ - cmd_Address_R

    cmd_Address_T               db "AT+ADDRESS=7776", 13, 10                    ; Transmitter Address
    cmd_Address_T_len           equ $ - cmd_Address_T

    arg_Dest_addr               db "7775,"                                      ; Destination Address
    arg_Dest_addr_len           equ $ - arg_Dest_addr

    configuration_prompt        db 10, "Configuring and tuning module...", 10
    configuration_prompt_len    equ $ - configuration_prompt

    transmission_prompt         db 10, "Transmission in progress...", 10
    transmission_prompt_len     equ $ - transmission_prompt

    reception_prompt            db 10, "Listening...", 10
    reception_prompt_len        equ $ - reception_prompt

    reception_complete_CRC      db 10, "Received message, validating CRC..."
    reception_complete_CRC_len  equ $ - reception_complete_CRC

    reception_complete_HMAC     db 10, "Validating HMAC..."
    reception_complete_HMAC_len equ $ - reception_complete_HMAC
    
    time_sleep                  dq 0, 20000000                                  ; Time delay between each frequency change (20 ms)

    ; =======================================================================
    ;                           EDITABLE SECTION END
    ; =======================================================================

    arg_Payload_length          db "45,"
    arg_Payload_length_len      equ $ - arg_Payload_length

    padding                     db "P"

%endif
