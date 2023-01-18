#include "kvm/devices.h"
#include "kvm/fdt.h"
#include "kvm/kvm.h"
#include "kvm/of_pci.h"
#include "kvm/pci.h"
#include "kvm/util.h"

/*
 * An entry in the interrupt-map table looks like:
 * <pci unit address> <pci interrupt pin> <irqchip phandle> <irqchip line>
 */

struct of_interrupt_map_entry {
	struct of_pci_irq_mask		pci_irq_mask;
	u32				irqchip_phandle;
	u32				irqchip_line;
	u32				irqchip_sense;
} __attribute__((packed));

void pci__generate_fdt_nodes(void *fdt)
{
	struct device_header *dev_hdr;
	struct of_interrupt_map_entry irq_map[OF_PCI_IRQ_MAP_MAX];
	unsigned nentries = 0, nsize;
	/* Bus range */
	u32 bus_range[] = { cpu_to_fdt32(0), cpu_to_fdt32(1), };
	/* Configuration Space */
	u64 cfg_reg_prop[] = { cpu_to_fdt64(KVM_PCI_CFG_AREA),
			       cpu_to_fdt64(RISCV_PCI_CFG_SIZE), };
	/* Describe the memory ranges */
	struct of_pci_ranges_entry ranges[] = {
		{
			.pci_addr = {
				.hi	= cpu_to_fdt32(of_pci_b_ss(OF_PCI_SS_IO)),
				.mid	= 0,
				.lo	= 0,
			},
			.cpu_addr	= cpu_to_fdt64(KVM_IOPORT_AREA),
			.length		= cpu_to_fdt64(RISCV_IOPORT_SIZE),
		},
		{
			.pci_addr = {
				.hi	= cpu_to_fdt32(of_pci_b_ss(OF_PCI_SS_M32)),
				.mid	= cpu_to_fdt32(KVM_PCI_MMIO_AREA >> 32),
				.lo	= cpu_to_fdt32(KVM_PCI_MMIO_AREA),
			},
			.cpu_addr	= cpu_to_fdt64(KVM_PCI_MMIO_AREA),
			.length		= cpu_to_fdt64(RISCV_PCI_MMIO_SIZE),
		},
	};

	/* Find size of each interrupt map entery */
	nsize = sizeof(struct of_interrupt_map_entry);
	if (!riscv_irqchip_line_sensing)
		nsize -= sizeof(u32);

	/* Boilerplate PCI properties */
	_FDT(fdt_begin_node(fdt, "pci"));
	_FDT(fdt_property_string(fdt, "device_type", "pci"));
	_FDT(fdt_property_cell(fdt, "#address-cells", 0x3));
	_FDT(fdt_property_cell(fdt, "#size-cells", 0x2));
	_FDT(fdt_property_cell(fdt, "#interrupt-cells", 0x1));
	_FDT(fdt_property_string(fdt, "compatible", "pci-host-ecam-generic"));
	_FDT(fdt_property(fdt, "dma-coherent", NULL, 0));

	_FDT(fdt_property(fdt, "bus-range", bus_range, sizeof(bus_range)));
	_FDT(fdt_property(fdt, "reg", &cfg_reg_prop, sizeof(cfg_reg_prop)));
	_FDT(fdt_property(fdt, "ranges", ranges, sizeof(ranges)));

	/* Generate the interrupt map ... */
	dev_hdr = device__first_dev(DEVICE_BUS_PCI);
	while (dev_hdr && nentries < ARRAY_SIZE(irq_map)) {
		struct of_interrupt_map_entry *entry;
		struct pci_device_header *pci_hdr = dev_hdr->data;
		u8 dev_num = dev_hdr->dev_num;
		u8 pin = pci_hdr->irq_pin;
		u8 irq = pci_hdr->irq_line;

		entry = ((void *)irq_map) + (nsize * nentries);
		*entry = (struct of_interrupt_map_entry) {
			.pci_irq_mask = {
				.pci_addr = {
					.hi	= cpu_to_fdt32(of_pci_b_ddddd(dev_num)),
					.mid	= 0,
					.lo	= 0,
				},
				.pci_pin	= cpu_to_fdt32(pin),
			},
			.irqchip_phandle	= cpu_to_fdt32(riscv_irqchip_phandle),
			.irqchip_line		= cpu_to_fdt32(irq),
		};

		if (riscv_irqchip_line_sensing)
			entry->irqchip_sense = cpu_to_fdt32(IRQ_TYPE_LEVEL_HIGH);

		nentries++;
		dev_hdr = device__next_dev(dev_hdr);
	}

	_FDT(fdt_property(fdt, "interrupt-map", irq_map, nsize * nentries));

	/* ... and the corresponding mask. */
	if (nentries) {
		struct of_pci_irq_mask irq_mask = {
			.pci_addr = {
				.hi	= cpu_to_fdt32(of_pci_b_ddddd(-1)),
				.mid	= 0,
				.lo	= 0,
			},
			.pci_pin	= cpu_to_fdt32(7),
		};

		_FDT(fdt_property(fdt, "interrupt-map-mask", &irq_mask,
				  sizeof(irq_mask)));
	}

	/* Set MSI parent if available */
	if (riscv_irqchip_msi_phandle != PHANDLE_RESERVED)
		_FDT(fdt_property_cell(fdt, "msi-parent", riscv_irqchip_msi_phandle));

	_FDT(fdt_end_node(fdt));
}
