/*
 * Copyright (c) 2014-2018 Netronome Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from this
 *  software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * vim:shiftwidth=8:noexpandtab
 *
 * @file dpdk/pmd/nfp_net_pmd.h
 *
 * Netronome NFP_NET PDM driver
 */

#include <linux/types.h>
#include <rte_io.h>

static inline uint8_t nn_readb(volatile const void *addr)
{
	return rte_read8(addr);
}

static inline void nn_writeb(uint8_t val, volatile void *addr)
{
	rte_write8(val, addr);
}

static inline uint32_t nn_readl(volatile const void *addr)
{
	return rte_read32(addr);
}

static inline void nn_writel(uint32_t val, volatile void *addr)
{
	rte_write32(val, addr);
}

static inline void nn_writew(uint16_t val, volatile void *addr)
{
	rte_write16(val, addr);
}

static inline uint64_t nn_readq(volatile void *addr)
{
	const volatile uint32_t *p = addr;
	uint32_t low, high;

	high = nn_readl((volatile const void *)(p + 1));
	low = nn_readl((volatile const void *)p);

	return low + ((uint64_t)high << 32);
}

static inline void nn_writeq(uint64_t val, volatile void *addr)
{
	nn_writel(val >> 32, (volatile char *)addr + 4);
	nn_writel(val, addr);
}

