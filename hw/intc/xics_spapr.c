/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * PAPR Virtualized Interrupt System, aka ICS/ICP aka xics
 *
 * Copyright (c) 2010,2011 David Gibson, IBM Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include "hw/hw.h"
#include "trace.h"
#include "qemu/timer.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/xics.h"
#include "qemu/error-report.h"
#include "qapi/visitor.h"

/*
 * Guest interfaces
 */

static target_ulong h_cppr(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    target_ulong cppr = args[0];

    icp_set_cppr(spapr->xics, cs->cpu_index, cppr);
    return H_SUCCESS;
}

static target_ulong h_ipi(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          target_ulong opcode, target_ulong *args)
{
    target_ulong server = get_cpu_index_by_dt_id(args[0]);
    target_ulong mfrr = args[1];

    if (server >= spapr->xics->nr_servers) {
        return H_PARAMETER;
    }

    icp_set_mfrr(spapr->xics, server, mfrr);
    return H_SUCCESS;
}

static target_ulong h_xirr(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    uint32_t xirr = icp_accept(spapr->xics->ss + cs->cpu_index);

    args[0] = xirr;
    return H_SUCCESS;
}

static target_ulong h_xirr_x(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                             target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    ICPState *ss = &spapr->xics->ss[cs->cpu_index];
    uint32_t xirr = icp_accept(ss);

    args[0] = xirr;
    args[1] = cpu_get_real_ticks();
    return H_SUCCESS;
}

static target_ulong h_eoi(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    target_ulong xirr = args[0];

    icp_eoi(spapr->xics, cs->cpu_index, xirr);
    return H_SUCCESS;
}

static target_ulong h_ipoll(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                            target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    uint32_t mfrr;
    uint32_t xirr = icp_ipoll(spapr->xics->ss + cs->cpu_index, &mfrr);

    args[0] = xirr;
    args[1] = mfrr;

    return H_SUCCESS;
}

static void rtas_set_xive(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          uint32_t token,
                          uint32_t nargs, target_ulong args,
                          uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, src_no, server, priority;

    if ((nargs != 3) || (nret != 1) || !ics) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);
    server = get_cpu_index_by_dt_id(rtas_ld(args, 1));
    priority = rtas_ld(args, 2);

    if (!ics_valid_irq(ics, nr) || (server >= ics->xics->nr_servers)
        || (priority > 0xff)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    src_no = nr - ics->offset;
    ics_simple_write_xive(ics, src_no, server, priority, priority);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_get_xive(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          uint32_t token,
                          uint32_t nargs, target_ulong args,
                          uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, src_no;

    if ((nargs != 1) || (nret != 3) || !ics) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);

    if (!ics_valid_irq(ics, nr)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    src_no = nr - ics->offset;
    rtas_st(rets, 1, ics->irqs[src_no].server);
    rtas_st(rets, 2, ics->irqs[src_no].priority);
}

static void rtas_int_off(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                         uint32_t token,
                         uint32_t nargs, target_ulong args,
                         uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, src_no;

    if ((nargs != 1) || (nret != 1) || !ics) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);

    if (!ics_valid_irq(ics, nr)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    src_no = nr - ics->offset;
    ics_simple_write_xive(ics, src_no, ics->irqs[src_no].server, 0xff,
                          ics->irqs[src_no].priority);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_int_on(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                        uint32_t token,
                        uint32_t nargs, target_ulong args,
                        uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, src_no;

    if ((nargs != 1) || (nret != 1) || !ics) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);

    if (!ics_valid_irq(ics, nr)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    src_no = nr - ics->offset;
    ics_simple_write_xive(ics, src_no, ics->irqs[src_no].server,
                          ics->irqs[src_no].saved_priority,
                          ics->irqs[src_no].saved_priority);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void xics_spapr_realize(DeviceState *dev, Error **errp)
{
    XICSState *xics = XICS(dev);
    ICSState *ics;
    Error *error = NULL;
    int i;

    if (!xics->nr_servers) {
        error_setg(errp, "Number of servers needs to be greater 0");
        return;
    }

    /* Registration of global state belongs into realize */
    spapr_rtas_register(RTAS_IBM_SET_XIVE, "ibm,set-xive", rtas_set_xive);
    spapr_rtas_register(RTAS_IBM_GET_XIVE, "ibm,get-xive", rtas_get_xive);
    spapr_rtas_register(RTAS_IBM_INT_OFF, "ibm,int-off", rtas_int_off);
    spapr_rtas_register(RTAS_IBM_INT_ON, "ibm,int-on", rtas_int_on);

    spapr_register_hypercall(H_CPPR, h_cppr);
    spapr_register_hypercall(H_IPI, h_ipi);
    spapr_register_hypercall(H_XIRR, h_xirr);
    spapr_register_hypercall(H_XIRR_X, h_xirr_x);
    spapr_register_hypercall(H_EOI, h_eoi);
    spapr_register_hypercall(H_IPOLL, h_ipoll);

    QLIST_FOREACH(ics, &xics->ics, list) {
        object_property_set_bool(OBJECT(ics), true, "realized", &error);
        if (error) {
            error_propagate(errp, error);
            return;
        }
    }

    for (i = 0; i < xics->nr_servers; i++) {
        object_property_set_bool(OBJECT(&xics->ss[i]), true, "realized", &error);
        if (error) {
            error_propagate(errp, error);
            return;
        }
    }
}

static void xics_spapr_initfn(Object *obj)
{
    XICSState *xics = XICS(obj);
    ICSState *ics;

    QLIST_INIT(&xics->ics);

    ics = ICS(object_new(TYPE_ICS_SIMPLE));
    object_property_add_child(obj, "ics", OBJECT(ics), NULL);
    xics_add_ics(xics, ics);
}

static void xics_spapr_set_nr_irqs(XICSState *xics, uint32_t nr_irqs, Error **errp)
{
    ICSState *ics = QLIST_FIRST(&xics->ics);

    /* This needs to be deprecated ... */
    xics->nr_irqs = nr_irqs;
    if (ics) {
        ics->nr_irqs = nr_irqs;
    }
}

static void xics_spapr_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    XICSStateClass *xsc = XICS_SPAPR_CLASS(oc);

    dc->realize = xics_spapr_realize;
    xsc->set_nr_irqs = xics_spapr_set_nr_irqs;
    xsc->set_nr_servers = xics_set_nr_servers;
}

static const TypeInfo xics_spapr_info = {
    .name          = TYPE_XICS_SPAPR,
    .parent        = TYPE_XICS_COMMON,
    .instance_size = sizeof(XICSState),
    .class_size = sizeof(XICSStateClass),
    .class_init    = xics_spapr_class_init,
    .instance_init = xics_spapr_initfn,
};

#define ICS_IRQ_FREE(ics, srcno)   \
    (!((ics)->irqs[(srcno)].flags & (XICS_FLAGS_IRQ_MASK)))

static int ics_find_free_block(ICSState *ics, int num, int alignnum)
{
    int first, i;

    for (first = 0; first < ics->nr_irqs; first += alignnum) {
        if (num > (ics->nr_irqs - first)) {
            return -1;
        }
        for (i = first; i < first + num; ++i) {
            if (!ICS_IRQ_FREE(ics, i)) {
                break;
            }
        }
        if (i == (first + num)) {
            return first;
        }
    }

    return -1;
}

int xics_spapr_alloc(XICSState *xics, int irq_hint, bool lsi)
{
    ICSState *ics = QLIST_FIRST(&xics->ics);
    int irq;

    if (!ics) {
        return -1;
    }
    if (irq_hint) {
        if (!ICS_IRQ_FREE(ics, irq_hint - ics->offset)) {
            trace_xics_alloc_failed_hint(0, irq_hint);
            return -1;
        }
        irq = irq_hint;
    } else {
        irq = ics_find_free_block(ics, 1, 1);
        if (irq < 0) {
            trace_xics_alloc_failed_no_left(0);
            return -1;
        }
        irq += ics->offset;
    }

    ics_simple_set_irq_type(ics, irq - ics->offset, lsi);
    trace_xics_alloc(0, irq);

    return irq;
}

/*
 * Allocate block of consequtive IRQs, returns a number of the first.
 * If align==true, aligns the first IRQ number to num.
 */
int xics_spapr_alloc_block(XICSState *xics, int num, bool lsi, bool align)
{
    ICSState *ics = QLIST_FIRST(&xics->ics);
    int i, first = -1;

    if (!ics) {
        return -1;
    }

    /*
     * MSIMesage::data is used for storing VIRQ so
     * it has to be aligned to num to support multiple
     * MSI vectors. MSI-X is not affected by this.
     * The hint is used for the first IRQ, the rest should
     * be allocated continuously.
     */
    if (align) {
        assert((num == 1) || (num == 2) || (num == 4) ||
               (num == 8) || (num == 16) || (num == 32));
        first = ics_find_free_block(ics, num, num);
    } else {
        first = ics_find_free_block(ics, num, 1);
    }

    if (first >= 0) {
        for (i = first; i < first + num; ++i) {
            ics_simple_set_irq_type(ics, i, lsi);
        }
    }
    first += ics->offset;

    trace_xics_alloc_block(0, first, num, lsi, align);

    return first;
}

static void ics_free(ICSState *ics, int srcno, int num)
{
    int i;

    for (i = srcno; i < srcno + num; ++i) {
        if (ICS_IRQ_FREE(ics, i)) {
            trace_xics_ics_free_warn(0, i + ics->offset);
        }
        memset(&ics->irqs[i], 0, sizeof(ICSIRQState));
    }
}

void xics_spapr_free(XICSState *xics, int irq, int num)
{
    ICSState *ics = xics_find_source(xics, irq);

    if (ics) {
        trace_xics_ics_free(0, irq, num);
        ics_free(ics, irq - ics->offset, num);
    }
}

static void xics_spapr_register_types(void)
{
    type_register_static(&xics_spapr_info);
}

type_init(xics_spapr_register_types)