/*
 *  PowerPC MMU, TLB, SLB and BAT emulation helpers for QEMU.
 *
 *  Copyright (c) 2003-2007 Jocelyn Mayer
 *  Copyright (c) 2013 David Gibson, IBM Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "cpu.h"
#include "exec/helper-proto.h"
#include "sysemu/kvm.h"
#include "kvm_ppc.h"
#include "mmu-hash64.h"

//#define DEBUG_MMU
//#define DEBUG_SLB

#ifdef DEBUG_MMU
#  define LOG_MMU_STATE(cpu) log_cpu_state((cpu), 0)
#else
#  define LOG_MMU_STATE(cpu) do { } while (0)
#endif

#ifdef DEBUG_SLB
#  define LOG_SLB(...) qemu_log(__VA_ARGS__)
#else
#  define LOG_SLB(...) do { } while (0)
#endif

/*
 * Used to indicate whether we have allocated htab in the
 * host kernel
 */
bool kvmppc_kern_htab;
/*
 * SLB handling
 */

static ppc_slb_t *slb_lookup(CPUPPCState *env, target_ulong eaddr)
{
    uint64_t esid_256M, esid_1T;
    int n;

    LOG_SLB("%s: eaddr " TARGET_FMT_lx "\n", __func__, eaddr);

    esid_256M = (eaddr & SEGMENT_MASK_256M) | SLB_ESID_V;
    esid_1T = (eaddr & SEGMENT_MASK_1T) | SLB_ESID_V;

    for (n = 0; n < env->slb_nr; n++) {
        ppc_slb_t *slb = &env->slb[n];

        LOG_SLB("%s: slot %d %016" PRIx64 " %016"
                    PRIx64 "\n", __func__, n, slb->esid, slb->vsid);
        /* We check for 1T matches on all MMUs here - if the MMU
         * doesn't have 1T segment support, we will have prevented 1T
         * entries from being inserted in the slbmte code. */
        if (((slb->esid == esid_256M) &&
             ((slb->vsid & SLB_VSID_B) == SLB_VSID_B_256M))
            || ((slb->esid == esid_1T) &&
                ((slb->vsid & SLB_VSID_B) == SLB_VSID_B_1T))) {
            return slb;
        }
    }

    return NULL;
}

void dump_slb(FILE *f, fprintf_function cpu_fprintf, CPUPPCState *env)
{
    int i;
    uint64_t slbe, slbv;

    cpu_synchronize_state(CPU(ppc_env_get_cpu(env)));

    cpu_fprintf(f, "SLB\tESID\t\t\tVSID\n");
    for (i = 0; i < env->slb_nr; i++) {
        slbe = env->slb[i].esid;
        slbv = env->slb[i].vsid;
        if (slbe == 0 && slbv == 0) {
            continue;
        }
        cpu_fprintf(f, "%d\t0x%016" PRIx64 "\t0x%016" PRIx64 "\n",
                    i, slbe, slbv);
    }
}

void helper_slbia(CPUPPCState *env)
{
    int n;

    /* XXX: Warning: slbia never invalidates the first segment */
    for (n = 1; n < env->slb_nr; n++) {
        ppc_slb_t *slb = &env->slb[n];

        if (slb->esid & SLB_ESID_V) {
            slb->esid &= ~SLB_ESID_V;
            /* XXX: given the fact that segment size is 256 MB or 1TB,
             *      and we still don't have a tlb_flush_mask(env, n, mask)
             *      in QEMU, we just invalidate all TLBs
             */
            env->tlb_need_flush = true;
        }
    }
}

void helper_slbie(CPUPPCState *env, target_ulong addr)
{
    ppc_slb_t *slb;

    slb = slb_lookup(env, addr);
    if (!slb) {
        return;
    }

    if (slb->esid & SLB_ESID_V) {
        slb->esid &= ~SLB_ESID_V;

        /* XXX: given the fact that segment size is 256 MB or 1TB,
         *      and we still don't have a tlb_flush_mask(env, n, mask)
         *      in QEMU, we just invalidate all TLBs
         */
        env->tlb_need_flush = true;
    }
}

int ppc_store_slb(CPUPPCState *env, target_ulong rb, target_ulong rs)
{
    int slot = rb & 0xfff;
    ppc_slb_t *slb = &env->slb[slot];

    if (rb & (0x1000 - env->slb_nr)) {
        return -1; /* Reserved bits set or slot too high */
    }
    if (rs & (SLB_VSID_B & ~SLB_VSID_B_1T)) {
        return -1; /* Bad segment size */
    }
    if ((rs & SLB_VSID_B) && !(env->mmu_model & POWERPC_MMU_1TSEG)) {
        return -1; /* 1T segment on MMU that doesn't support it */
    }

    /* Mask out the slot number as we store the entry */
    slb->esid = rb & (SLB_ESID_ESID | SLB_ESID_V);
    slb->vsid = rs;

    LOG_SLB("%s: %d " TARGET_FMT_lx " - " TARGET_FMT_lx " => %016" PRIx64
            " %016" PRIx64 "\n", __func__, slot, rb, rs,
            slb->esid, slb->vsid);

    return 0;
}

static int ppc_load_slb_esid(CPUPPCState *env, target_ulong rb,
                             target_ulong *rt)
{
    int slot = rb & 0xfff;
    ppc_slb_t *slb = &env->slb[slot];

    if (slot >= env->slb_nr) {
        return -1;
    }

    *rt = slb->esid;
    return 0;
}

static int ppc_load_slb_vsid(CPUPPCState *env, target_ulong rb,
                             target_ulong *rt)
{
    int slot = rb & 0xfff;
    ppc_slb_t *slb = &env->slb[slot];

    if (slot >= env->slb_nr) {
        return -1;
    }

    *rt = slb->vsid;
    return 0;
}

static int ppc_find_slb_esid(CPUPPCState *env, target_ulong rb,
                             target_ulong *rt)
{
    ppc_slb_t *slb = slb_lookup(env, rb);

    if (!slb) {
        return -1;
    }

    *rt = slb->vsid;
    return 0;
}

void helper_store_slb(CPUPPCState *env, target_ulong rb, target_ulong rs)
{
    if (ppc_store_slb(env, rb, rs) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
}

target_ulong helper_load_slb_esid(CPUPPCState *env, target_ulong rb)
{
    target_ulong rt = 0;

    if (ppc_load_slb_esid(env, rb, &rt) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
    return rt;
}

target_ulong helper_load_slb_vsid(CPUPPCState *env, target_ulong rb)
{
    target_ulong rt = 0;

    if (ppc_load_slb_vsid(env, rb, &rt) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
    return rt;
}

target_ulong helper_find_slb_esid(CPUPPCState *env, target_ulong rb)
{
    target_ulong rt = 0;

    if (ppc_find_slb_esid(env, rb, &rt) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
    return rt;
}

/*
 * 64-bit hash table MMU handling
 */

static int ppc_hash64_pte_prot(CPUPPCState *env,
                               ppc_slb_t *slb, ppc_hash_pte64_t pte)
{
    unsigned pp, key;
    /* Some pp bit combinations have undefined behaviour, so default
     * to no access in those cases */
    int prot = 0;

    key = !!(msr_pr ? (slb->vsid & SLB_VSID_KP)
             : (slb->vsid & SLB_VSID_KS));
    pp = (pte.pte1 & HPTE64_R_PP) | ((pte.pte1 & HPTE64_R_PP0) >> 61);

    if (key == 0) {
        switch (pp) {
        case 0x0:
        case 0x1:
        case 0x2:
            prot = PAGE_READ | PAGE_WRITE;
            break;

        case 0x3:
        case 0x6:
            prot = PAGE_READ;
            break;
        }
    } else {
        switch (pp) {
        case 0x0:
        case 0x6:
            prot = 0;
            break;

        case 0x1:
        case 0x3:
            prot = PAGE_READ;
            break;

        case 0x2:
            prot = PAGE_READ | PAGE_WRITE;
            break;
        }
    }

    /* No execute if either noexec or guarded bits set */
    if (!(pte.pte1 & HPTE64_R_N) || (pte.pte1 & HPTE64_R_G)
        || (slb->vsid & SLB_VSID_N)) {
        prot |= PAGE_EXEC;
    }

    return prot;
}

static int ppc_hash64_amr_prot(CPUPPCState *env, ppc_hash_pte64_t pte)
{
    int key, amrbits;
    int prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;


    /* Only recent MMUs implement Virtual Page Class Key Protection */
    if (!(env->mmu_model & POWERPC_MMU_AMR)) {
        return prot;
    }

    key = HPTE64_R_KEY(pte.pte1);
    amrbits = (env->spr[SPR_AMR] >> 2*(31 - key)) & 0x3;

    /* fprintf(stderr, "AMR protection: key=%d AMR=0x%" PRIx64 "\n", key, */
    /*         env->spr[SPR_AMR]); */

    /*
     * A store is permitted if the AMR bit is 0. Remove write
     * protection if it is set.
     */
    if (amrbits & 0x2) {
        prot &= ~PAGE_WRITE;
    }
    /*
     * A load is permitted if the AMR bit is 0. Remove read
     * protection if it is set.
     */
    if (amrbits & 0x1) {
        prot &= ~PAGE_READ;
    }

    return prot;
}

uint64_t ppc_hash64_start_access(PowerPCCPU *cpu, target_ulong pte_index)
{
    uint64_t token = 0;
    hwaddr pte_offset;

    pte_offset = pte_index * HASH_PTE_SIZE_64;
    if (kvmppc_kern_htab) {
        /*
         * HTAB is controlled by KVM. Fetch the PTEG into a new buffer.
         */
        token = kvmppc_hash64_read_pteg(cpu, pte_index);
        if (token) {
            return token;
        }
        /*
         * pteg read failed, even though we have allocated htab via
         * kvmppc_reset_htab.
         */
        return 0;
    }
    /*
     * HTAB is controlled by QEMU. Just point to the internally
     * accessible PTEG.
     */
    if (cpu->env.external_htab) {
        token = (uint64_t)(uintptr_t) cpu->env.external_htab + pte_offset;
    } else if (cpu->env.htab_base) {
        token = cpu->env.htab_base + pte_offset;
    }
    return token;
}

void ppc_hash64_stop_access(uint64_t token)
{
    if (kvmppc_kern_htab) {
        kvmppc_hash64_free_pteg(token);
    }
}

/* Returns the effective page shift or 0. MPSS isn't supported yet so
 * this will always be the slb_pshift or 0
 */
static uint32_t ppc_hash64_pte_size_decode(uint64_t pte1, uint32_t slb_pshift)
{
    switch(slb_pshift) {
    case 12:
        return 12;
    case 16:
        if ((pte1 & 0xf000) == 0x1000) {
            return 16;
        }
        return 0;
    case 24:
        if ((pte1 & 0xff000) == 0) {
            return 24;
        }
        return 0;
    }
    return 0;
}

static hwaddr ppc_hash64_pteg_search(CPUPPCState *env, hwaddr hash,
                                     uint32_t slb_pshift, bool secondary,
                                     target_ulong ptem, ppc_hash_pte64_t *pte)
{
    int i;
    uint64_t token;
    target_ulong pte0, pte1;
    target_ulong pte_index;

    pte_index = (hash & env->htab_mask) * HPTES_PER_GROUP;
    token = ppc_hash64_start_access(ppc_env_get_cpu(env), pte_index);
    if (!token) {
        return -1;
    }
    for (i = 0; i < HPTES_PER_GROUP; i++) {
        pte0 = ppc_hash64_load_hpte0(env, token, i);
        pte1 = ppc_hash64_load_hpte1(env, token, i);

        if ((pte0 & HPTE64_V_VALID)
            && (secondary == !!(pte0 & HPTE64_V_SECONDARY))
            && HPTE64_V_COMPARE(pte0, ptem)) {
            uint32_t pshift = ppc_hash64_pte_size_decode(pte1, slb_pshift);
            if (pshift == 0) {
                continue;
            }
            /* We don't do anything with pshift yet as qemu TLB only deals
             * with 4K pages anyway
             */
            pte->pte0 = pte0;
            pte->pte1 = pte1;
            ppc_hash64_stop_access(token);
            return (pte_index + i) * HASH_PTE_SIZE_64;
        }
    }
    ppc_hash64_stop_access(token);
    /*
     * We didn't find a valid entry.
     */
    return -1;
}

static uint64_t ppc_hash64_page_shift(CPUPPCState *env, ppc_slb_t *slb)
{
    uint64_t epnshift;

    /* Page size according to the SLB, which we use to generate the
     * EPN for hash table lookup..  When we implement more recent MMU
     * extensions this might be different from the actual page size
     * encoded in the PTE */
    if ((slb->vsid & SLB_VSID_LLP_MASK) == SLB_VSID_4K) {
        epnshift = TARGET_PAGE_BITS;
    } else if ((slb->vsid & SLB_VSID_LLP_MASK) == SLB_VSID_64K &&
               (env->mmu_model & POWERPC_MMU_64K)) {
        epnshift = TARGET_PAGE_BITS_64K;
    } else {
        epnshift = TARGET_PAGE_BITS_16M;
    }
    return epnshift;
}

static hwaddr ppc_hash64_htab_lookup(CPUPPCState *env,
                                     ppc_slb_t *slb, target_ulong eaddr,
                                     ppc_hash_pte64_t *pte)
{
    hwaddr pte_offset;
    hwaddr hash;
    uint64_t vsid, epnshift, epnmask, epn, ptem;

    epnshift = ppc_hash64_page_shift(env, slb);
    epnmask = ~((1ULL << epnshift) - 1);

    if (slb->vsid & SLB_VSID_B) {
        /* 1TB segment */
        vsid = (slb->vsid & SLB_VSID_VSID) >> SLB_VSID_SHIFT_1T;
        epn = (eaddr & ~SEGMENT_MASK_1T) & epnmask;
        hash = vsid ^ (vsid << 25) ^ (epn >> epnshift);
    } else {
        /* 256M segment */
        vsid = (slb->vsid & SLB_VSID_VSID) >> SLB_VSID_SHIFT;
        epn = (eaddr & ~SEGMENT_MASK_256M) & epnmask;
        hash = vsid ^ (epn >> epnshift);
    }
    ptem = (slb->vsid & SLB_VSID_PTEM) | ((epn >> 16) & HPTE64_V_AVPN);

    /* Page address translation */
    qemu_log_mask(CPU_LOG_MMU,
            "htab_base " TARGET_FMT_plx " htab_mask " TARGET_FMT_plx
            " hash " TARGET_FMT_plx "\n",
            env->htab_base, env->htab_mask, hash);

    /* Primary PTEG lookup */
    qemu_log_mask(CPU_LOG_MMU,
            "0 htab=" TARGET_FMT_plx "/" TARGET_FMT_plx
            " vsid=" TARGET_FMT_lx " ptem=" TARGET_FMT_lx
            " hash=" TARGET_FMT_plx "\n",
            env->htab_base, env->htab_mask, vsid, ptem,  hash);
    pte_offset = ppc_hash64_pteg_search(env, hash, epnshift, 0, ptem, pte);

    if (pte_offset == -1) {
        /* Secondary PTEG lookup */
        qemu_log_mask(CPU_LOG_MMU,
                "1 htab=" TARGET_FMT_plx "/" TARGET_FMT_plx
                " vsid=" TARGET_FMT_lx " api=" TARGET_FMT_lx
                " hash=" TARGET_FMT_plx "\n", env->htab_base,
                env->htab_mask, vsid, ptem, ~hash);

        pte_offset = ppc_hash64_pteg_search(env, ~hash, epnshift, 1, ptem, pte);
    }

    return pte_offset;
}

static hwaddr ppc_hash64_pte_raddr(CPUPPCState *env, ppc_slb_t *slb,
                                   ppc_hash_pte64_t pte, target_ulong eaddr)
{
    hwaddr mask;
    int target_page_bits;
    hwaddr rpn = pte.pte1 & HPTE64_R_RPN;
    /*
     * We support 4K, 64K and 16M now
     */
    target_page_bits = ppc_hash64_page_shift(env, slb);
    mask = (1ULL << target_page_bits) - 1;
    return (rpn & ~mask) | (eaddr & mask);
}

static void ppc_hash64_set_isi(CPUState *cs, CPUPPCState *env, uint64_t error_code)
{
    bool vpm;

    if (msr_ir) {
        vpm = !!(env->spr[SPR_LPCR] & LPCR_VPM1);
    } else {
        vpm = !!(env->spr[SPR_LPCR] & LPCR_VPM0);
    }
    if (vpm) {
        cs->exception_index = POWERPC_EXCP_HISI;
    } else {
        cs->exception_index = POWERPC_EXCP_ISI;
    }
    env->error_code = error_code;
}

static void ppc_hash64_set_dsi(CPUState *cs, CPUPPCState *env, uint64_t dar, uint64_t dsisr)
{
    bool vpm;

    if (msr_dr) {
        vpm = !!(env->spr[SPR_LPCR] & LPCR_VPM1);
    } else {
        vpm = !!(env->spr[SPR_LPCR] & LPCR_VPM0);
    }
    if (vpm) {
        cs->exception_index = POWERPC_EXCP_HDSI;
        env->spr[SPR_HDAR] = dar;
        env->spr[SPR_HDSISR] = dsisr;
    } else {
        cs->exception_index = POWERPC_EXCP_DSI;
        env->spr[SPR_DAR] = dar;
        env->spr[SPR_DSISR] = dsisr;
   }
    env->error_code = 0;
}

static int64_t ppc_hash64_get_rmls(CPUPPCState *env)
{
    uint64_t lpcr = env->spr[SPR_LPCR];

    /*
     * This is the full 4 bits encoding of POWER8. Previous
     * CPUs only support a subset of these but the filtering
     * is done when writing LPCR
     */
    switch((lpcr & LPCR_RMLS) >> LPCR_RMLS_SHIFT) {
    case 0x8: /* 32MB */
        return 0x2000000ull;
    case 0x3: /* 64MB */
        return 0x4000000ull;
    case 0x7: /* 128MB */
        return 0x8000000ull;
    case 0x4: /* 256MB */
        return 0x10000000ull;
    case 0x2: /* 1GB */
        return 0x40000000ull;
    case 0x1: /* 16GB */
        return 0x400000000ull;
    default:
        /* What to do here ??? */
        return 0;
    }
}

int ppc_hash64_handle_mmu_fault(PowerPCCPU *cpu, target_ulong eaddr,
                                int rwx, int mmu_idx)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    ppc_slb_t *slb_ptr;
    ppc_slb_t slb;
    hwaddr pte_offset;
    ppc_hash_pte64_t pte;
    int pp_prot, amr_prot, prot;
    uint64_t new_pte1, dsisr;
    const int need_prot[] = {PAGE_READ, PAGE_WRITE, PAGE_EXEC};
    hwaddr raddr;

    assert((rwx == 0) || (rwx == 1) || (rwx == 2));

    /* Note on LPCR usage: 970 uses HID4, but our special variant
     * of store_spr copies relevant fields into env->spr[SPR_LPCR].
     * Similarily we filter unimplemented bits when storing into
     * LPCR depending on the MMU version. This code can thus just
     * use the LPCR "as-is".
     */

    /* 1. Handle real mode accesses */
    if (((rwx == 2) && (msr_ir == 0)) || ((rwx != 2) && (msr_dr == 0))) {
        /* Translation is supposedly "off"  */
        /* In real mode the top 4 effective address bits are (mostly) ignored */
        raddr = eaddr & 0x0FFFFFFFFFFFFFFFULL;

        /* In HV mode, add HRMOR if top EA bit is clear */
        if (msr_hv) {
            if (!(eaddr >> 63)) {
                raddr |= env->spr[SPR_HRMOR];
            }
        } else {
            /* Otherwise, check VPM for RMA vs VRMA */
            if (env->spr[SPR_LPCR] & LPCR_VPM0) {
                uint32_t vrmasd;
                /* VRMA, we make up an SLB entry */
                slb.vsid = SLB_VSID_VRMA;
                vrmasd = (env->spr[SPR_LPCR] & LPCR_VRMASD) >> LPCR_VRMASD_SHIFT;
                slb.vsid |= (vrmasd << 4) & (SLB_VSID_L | SLB_VSID_LP);
                slb.esid = SLB_ESID_V;
                goto skip_slb;
            }
            /* RMA. Check bounds in RMLS */
            if (raddr < ppc_hash64_get_rmls(env)) {
              raddr |= env->spr[SPR_RMOR];
            } else {
                /* The access failed, generate the approriate interrupt */
                if (rwx == 2) {
                    ppc_hash64_set_isi(cs, env, 0x08000000);
                } else {
                    dsisr = 0x08000000;
                    if (rwx == 1) {
                        dsisr |= 0x02000000;
                    }
                    ppc_hash64_set_dsi(cs, env, eaddr, dsisr);
                }
                return 1;
            }
        }
        tlb_set_page(cs, eaddr & TARGET_PAGE_MASK, raddr & TARGET_PAGE_MASK,
                     PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx,
                     TARGET_PAGE_SIZE);
        return 0;
    }

    /* 2. Translation is on, so look up the SLB */
    slb_ptr = slb_lookup(env, eaddr);
    if (!slb_ptr) {
        if (rwx == 2) {
            cs->exception_index = POWERPC_EXCP_ISEG;
            env->error_code = 0;
        } else {
            cs->exception_index = POWERPC_EXCP_DSEG;
            env->error_code = 0;
            env->spr[SPR_DAR] = eaddr;
        }
        return 1;
    }

    /* We grab a local copy because we can modify it (or get a
     * pre-cooked one from the VRMA code
     */
    slb = *slb_ptr;

    /* 2.5 Clamp L||LP in ISL mode */
    if (env->spr[SPR_LPCR] & LPCR_ISL) {
         slb.vsid &= ~SLB_VSID_LLP_MASK;
    }

    /* 3. Check for segment level no-execute violation */
    if ((rwx == 2) && (slb.vsid & SLB_VSID_N)) {
        ppc_hash64_set_isi(cs, env, 0x10000000);
        return 1;
    }

    /* We go straight here for VRMA translations as none of the
     * above applies in that case
     */
 skip_slb:

    /* 4. Locate the PTE in the hash table */
    pte_offset = ppc_hash64_htab_lookup(env, &slb, eaddr, &pte);
    if (pte_offset == -1) {
        dsisr = 0x40000000;
        if (rwx == 2) {
            ppc_hash64_set_isi(cs, env, dsisr);
        } else {
            if (rwx == 1) {
                dsisr |= 0x02000000;
            }
            ppc_hash64_set_dsi(cs, env, eaddr, dsisr);
        }
        return 1;
    }
    qemu_log_mask(CPU_LOG_MMU,
                "found PTE at offset %08" HWADDR_PRIx "\n", pte_offset);

    /* 5. Check access permissions */

    pp_prot = ppc_hash64_pte_prot(env, &slb, pte);
    amr_prot = ppc_hash64_amr_prot(env, pte);
    prot = pp_prot & amr_prot;

    if ((need_prot[rwx] & ~prot) != 0) {
        /* Access right violation */
        qemu_log_mask(CPU_LOG_MMU, "PTE access rejected\n");
        if (rwx == 2) {
            ppc_hash64_set_isi(cs, env, 0x08000000);
        } else {
            dsisr = 0;
            if (need_prot[rwx] & ~pp_prot) {
                dsisr |= 0x08000000;
            }
            if (rwx == 1) {
                dsisr |= 0x02000000;
            }
            if (need_prot[rwx] & ~amr_prot) {
                dsisr |= 0x00200000;
            }
            ppc_hash64_set_dsi(cs, env, eaddr, dsisr);
        }
        return 1;
    }

    qemu_log_mask(CPU_LOG_MMU, "PTE access granted !\n");

    /* 6. Update PTE referenced and changed bits if necessary */

    new_pte1 = pte.pte1 | HPTE64_R_R; /* set referenced bit */
    if (rwx == 1) {
        new_pte1 |= HPTE64_R_C; /* set changed (dirty) bit */
    } else {
        /* Treat the page as read-only for now, so that a later write
         * will pass through this function again to set the C bit */
        prot &= ~PAGE_WRITE;
    }

    if (new_pte1 != pte.pte1) {
        ppc_hash64_store_hpte(env, pte_offset / HASH_PTE_SIZE_64,
                              pte.pte0, new_pte1);
    }

    /* 7. Determine the real address from the PTE */

    raddr = ppc_hash64_pte_raddr(env, &slb, pte, eaddr);

    tlb_set_page(cs, eaddr & TARGET_PAGE_MASK, raddr & TARGET_PAGE_MASK,
                 prot, mmu_idx, TARGET_PAGE_SIZE);

    return 0;
}

hwaddr ppc_hash64_get_phys_page_debug(CPUPPCState *env, target_ulong addr)
{
    ppc_slb_t slb;
    ppc_slb_t *slb_ptr;
    hwaddr pte_offset, raddr;
    ppc_hash_pte64_t pte;

    /* Handle real mode */
    if (msr_dr == 0) {
        raddr = addr & 0x0FFFFFFFFFFFFFFFULL;

        /* In HV mode, add HRMOR if top EA bit is clear */
        if (msr_hv & !(addr >> 63)) {
            return raddr | env->spr[SPR_HRMOR];
        }

        /* Otherwise, check VPM for RMA vs VRMA */
        if (env->spr[SPR_LPCR] & LPCR_VPM0) {
            uint32_t vrmasd;

            /* VRMA, we make up an SLB entry */
            slb.vsid = SLB_VSID_VRMA;
            vrmasd = (env->spr[SPR_LPCR] & LPCR_VRMASD) >> LPCR_VRMASD_SHIFT;
            slb.vsid |= (vrmasd << 4) & (SLB_VSID_L | SLB_VSID_LP);
            slb.esid = SLB_ESID_V;
            goto skip_slb;
        }
        /* RMA. Check bounds in RMLS */
        if (raddr < ppc_hash64_get_rmls(env)) {
            return raddr | env->spr[SPR_RMOR];
        }
        return -1;
    }

    slb_ptr = slb_lookup(env, addr);
    if (!slb_ptr) {
        return -1;
    }
    slb = *slb_ptr;
 skip_slb:
    pte_offset = ppc_hash64_htab_lookup(env, &slb, addr, &pte);
    if (pte_offset == -1) {
        return -1;
    }

    return ppc_hash64_pte_raddr(env, &slb, pte, addr) & TARGET_PAGE_MASK;
}

void ppc_hash64_store_hpte(CPUPPCState *env,
                           target_ulong pte_index,
                           target_ulong pte0, target_ulong pte1)
{
    CPUState *cs = CPU(ppc_env_get_cpu(env));

    if (kvmppc_kern_htab) {
        kvmppc_hash64_write_pte(env, pte_index, pte0, pte1);
        return;
    }

    pte_index *= HASH_PTE_SIZE_64;
    if (env->external_htab) {
        stq_p(env->external_htab + pte_index, pte0);
        stq_p(env->external_htab + pte_index + HASH_PTE_SIZE_64/2, pte1);
    } else {
        stq_phys(cs->as, env->htab_base + pte_index, pte0);
        stq_phys(cs->as, env->htab_base + pte_index + HASH_PTE_SIZE_64/2, pte1);
    }
}

void helper_store_lpcr(CPUPPCState *env, target_ulong val)
{
    uint64_t lpcr = 0;

    /* Filter out bits */
    switch(env->mmu_model) {
    case POWERPC_MMU_64B: /* 970 */
        if (val & 0x40) {
            lpcr |= LPCR_LPES0;
        }
        if (val & 0x8000000000000000ull) {
            lpcr |= LPCR_LPES1;
        }
        if (val & 0x20) {
            lpcr |= (0x4ull << LPCR_RMLS_SHIFT);
        }
        if (val & 0x4000000000000000ull) {
            lpcr |= (0x2ull << LPCR_RMLS_SHIFT);
        }
        if (val & 0x2000000000000000ull) {
            lpcr |= (0x1ull << LPCR_RMLS_SHIFT);
        }
        env->spr[SPR_RMOR] = ((lpcr >> 41) & 0xffffull) << 26;

        /* XXX We could also write LPID from HID4 here
         * but since we don't tag any translation on it
         * it doesn't actually matter
         */
        /* XXX For proper emulation of 970 we also need
         * to dig HRMOR out of HID5
         */
        break;
    case POWERPC_MMU_2_03: /* P5p */
        lpcr = val & (LPCR_RMLS | LPCR_ILE |
                      LPCR_LPES0 | LPCR_LPES1 |
                      LPCR_RMI | LPCR_HDICE);
        break;
    case POWERPC_MMU_2_06: /* P7 */
        lpcr = val & (LPCR_VPM0 | LPCR_VPM1 | LPCR_ISL | LPCR_DPFD |
                      LPCR_VRMASD | LPCR_RMLS | LPCR_ILE |
                      LPCR_P7_PECE0 | LPCR_P7_PECE1 | LPCR_P7_PECE2 |
                      LPCR_MER | LPCR_TC |
                      LPCR_LPES0 | LPCR_LPES1 | LPCR_HDICE);
        break;
    case POWERPC_MMU_2_07: /* P8 */
        lpcr = val & (LPCR_VPM0 | LPCR_VPM1 | LPCR_ISL | LPCR_KBV |
                      LPCR_DPFD | LPCR_VRMASD | LPCR_RMLS | LPCR_ILE |
                      LPCR_AIL | LPCR_ONL | LPCR_P8_PECE0 | LPCR_P8_PECE1 |
                      LPCR_P8_PECE2 | LPCR_P8_PECE3 | LPCR_P8_PECE4 |
                      LPCR_MER | LPCR_TC | LPCR_LPES0 | LPCR_HDICE);
        break;
    default:
        ;
    }
    env->spr[SPR_LPCR] = lpcr;
}

