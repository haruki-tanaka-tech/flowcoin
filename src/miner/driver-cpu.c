/*
 * CPU mining driver for FlowCoin (Keccak-256d)
 * Provides basic CPU mining capability using the Keccak-256d hash function.
 */
#include "config.h"
#include "miner.h"
#include "keccak2.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Forward declare the gen_hash from cgminer.c */
extern void gen_hash(unsigned char *data, unsigned char *hash, int len);

static void cpu_detect(bool __maybe_unused hotplug)
{
	struct cgpu_info *cgpu;

	cgpu = calloc(1, sizeof(*cgpu));
	if (!cgpu)
		return;

	cgpu->drv = &cpu_drv;
	cgpu->deven = DEV_ENABLED;
	cgpu->threads = 1;
	cgpu->kname = "CPU";
	cgpu->name = "CPU";

	add_cgpu(cgpu);
}

static bool cpu_thread_prepare(struct thr_info __maybe_unused *thr)
{
	return true;
}

static bool cpu_thread_init(struct thr_info __maybe_unused *thr)
{
	return true;
}

static int64_t cpu_scanhash(struct thr_info *thr, struct work *work, int64_t max_nonce)
{
	uint32_t *nonce_ptr = (uint32_t *)(work->data + 76);
	uint32_t first_nonce = *nonce_ptr;
	uint32_t n = first_nonce;
	unsigned char hash[32];
	int64_t hashes = 0;

	/* Target check: first 4 bytes of target should be non-zero for valid target */
	uint32_t *target32 = (uint32_t *)work->target;

	while (n < (uint32_t)max_nonce && !thr->work_restart) {
		*nonce_ptr = n;

		/* Keccak-256d: double hash the 80-byte header */
		keccak256d(work->data, 80, hash);

		hashes++;

		/* Quick check: compare last 4 bytes of hash with target */
		if (((uint32_t *)hash)[7] == 0) {
			/* Full target comparison */
			memcpy(work->hash, hash, 32);
			if (fulltest(work->hash, work->target)) {
				work->nonce = n;
				return hashes;
			}
		}

		n++;
	}

	return hashes;
}

static void cpu_thread_shutdown(struct thr_info __maybe_unused *thr)
{
}

static uint64_t cpu_can_limit_work(struct thr_info __maybe_unused *thr)
{
	return 1;
}

static int64_t cpu_scanwork(struct thr_info *thr)
{
	struct work *work = get_work(thr, thr->id);
	int64_t hashes;

	if (work->pool->has_stratum || work->pool->has_gbt) {
		hashes = cpu_scanhash(thr, work, work->nonce + 0xffffff);
	} else {
		hashes = cpu_scanhash(thr, work, work->nonce + 0xffffff);
	}

	free_work(work);
	return hashes;
}

struct device_drv cpu_drv = {
	.drv_id = DRIVER_cpu,
	.dname = "cpu",
	.name = "CPU",
	.drv_detect = cpu_detect,
	.thread_prepare = cpu_thread_prepare,
	.thread_init = cpu_thread_init,
	.scanhash = cpu_scanhash,
	.scanwork = cpu_scanwork,
	.thread_shutdown = cpu_thread_shutdown,
	.can_limit_work = cpu_can_limit_work,
};
