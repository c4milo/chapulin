#ifndef FREERTOS_IP_CONFIG_H
#define FREERTOS_IP_CONFIG_H

#define ipconfigUSE_IPv4 1
#define ipconfigUSE_IPv6 0
#define ipconfigUSE_TCP 1
#define ipconfigUSE_DHCP 0
#define ipconfigUSE_DHCPv6 0
#define ipconfigUSE_DNS 0
#define ipconfigUSE_LLMNR 0
#define ipconfigUSE_NBNS 0
#define ipconfigUSE_MDNS 0
#define ipconfigSUPPORT_OUTGOING_PINGS 0
#define ipconfigREPLY_TO_INCOMING_PINGS 0
#define ipconfigNETWORK_MTU 1500
#define ipconfigTCP_MSS 1400
#define ipconfigNUM_NETWORK_BUFFER_DESCRIPTORS 12
#define ipconfigEVENT_QUEUE_LENGTH (ipconfigNUM_NETWORK_BUFFER_DESCRIPTORS + 5)
#define ipconfigIP_TASK_PRIORITY (configMAX_PRIORITIES - 2)
#define ipconfigIP_TASK_STACK_SIZE_WORDS 512
#define ipconfigUSE_NETWORK_EVENT_HOOK 1
#define ipconfigZERO_COPY_RX_DRIVER 0
#define ipconfigZERO_COPY_TX_DRIVER 0
#define ipconfigSOCK_DEFAULT_RECEIVE_BLOCK_TIME pdMS_TO_TICKS(5000)
#define ipconfigSOCK_DEFAULT_SEND_BLOCK_TIME pdMS_TO_TICKS(5000)
#define ipconfigALLOW_SOCKET_SEND_WITHOUT_BIND 1
#define ipconfigTCP_KEEP_ALIVE 0
#define ipconfigDNS_USE_CALLBACKS 0
#define ipconfigSUPPORT_SELECT_FUNCTION 0
#define ipconfigSUPPORT_SIGNALS 0
#define ipconfigHAS_DEBUG_PRINTF 0
#define ipconfigHAS_PRINTF 0
#define ipconfigBYTE_ORDER pdFREERTOS_LITTLE_ENDIAN
#define ipconfigETHERNET_DRIVER_FILTERS_FRAME_TYPES 1
#define ipconfigETHERNET_DRIVER_FILTERS_PACKETS 0

#endif
