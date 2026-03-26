/*
 * Stub driver definitions for disabled ASIC/FPGA hardware.
 * FlowCoin uses Keccak-256d PoW — SHA-256d ASICs cannot mine it.
 */
#include "miner.h"

/* Zero-initialized stubs — all function pointers NULL, all fields zero */
struct device_drv bitforce_drv;
struct device_drv modminer_drv;
struct device_drv ants1_drv;
struct device_drv ants2_drv;
struct device_drv ants3_drv;
struct device_drv avalon_drv;
struct device_drv avalon2_drv;
struct device_drv avalon4_drv;
struct device_drv avalon7_drv;
struct device_drv avalon8_drv;
struct device_drv avalonm_drv;
struct device_drv bab_drv;
struct device_drv bflsc_drv;
struct device_drv bitfury_drv;
struct device_drv bitfury16_drv;
struct device_drv bitmineA1_drv;
struct device_drv blockerupter_drv;
struct device_drv cointerra_drv;
struct device_drv dragonmintT1_drv;
struct device_drv hashfast_drv;
struct device_drv drillbit_drv;
struct device_drv hashratio_drv;
struct device_drv icarus_drv;
struct device_drv klondike_drv;
struct device_drv knc_drv;
struct device_drv minion_drv;
struct device_drv sp10_drv;
struct device_drv sp30_drv;
struct device_drv bitmain_soc_drv;
