# Shopping list: S1 and S2

Prices are rough estimates [I]; check current listings. Total about **$250–400**, less if you already own PCs.

## S1: boot drive

| # | Item | Why | Est. |
|---|---|---|---|
| 1 | **USB4 NVMe enclosure, ASMedia ASM2464PD chip** (sold by Acasis, Zike, Orico, UGREEN and others) | The box's drive. Runs at 40 Gbps on USB4/Thunderbolt and falls back to 10 Gbps USB 3.2 on older ports | $60–100 |
| 2 | **NVMe M.2 2280 SSD, 500 GB–1 TB**, any mainstream TLC model | Goes in the enclosure | $40–70 |
| 3 | **USB-C to USB-A adapter or cable rated 10 Gbps** (skip if the enclosure includes one) | For PCs without USB-C | $10 |
| 4 | Optional: **USB 3.2 Gen 2 NVMe enclosure, Realtek RTL9210B** | Cheap comparison; dm-verity makes enclosure read errors fatal (S7), so a second chipset is useful evidence | $20 |

**PCs (borrow, don't buy):** at least 3 x86-64 PCs with UEFI from different vendors, made in roughly the last ten
years. Include the floor machine if you have it (N95 with 8 GB, e.g. GEEKOM Air12 Lite; HW-4). Not Macs (HW-7) and
not Windows-on-ARM laptops (HW-3). A monitor and keyboard nearby help diagnose a failure, but the pass test uses neither.

## S2: modems and SIM

| # | Item | Why | Est. |
|---|---|---|---|
| 5 | **Quectel EC25-AF** (North America) **or EG25-G**, as a USB dongle or mini-PCIe module in a USB adapter with SIM slot | Voice over USB Audio Class; widely used under Linux (ModemManager) | $50–90 |
| 6 | **SIMCom SIM7600G-H USB dongle** (e.g. Waveshare "SIM7600G-H 4G DONGLE") | Second vendor; voice as PCM over a serial port | $50–80 |
| 7 | **One prepaid SIM with voice and SMS, on a carrier that allows VoLTE on unlisted devices.** In the US that most likely means the T-Mobile network (T-Mobile prepaid or an MVNO on it) [I]. AT&T and Verizon allow-list device IMEIs, so a module may get data and SMS but no calls | 3G is gone, so calls need VoLTE | $10–25/mo |
| 8 | **LTE antennas** (2, u.FL or SMA to match) if the dongle or adapter doesn't include them | Modules don't work without them | $10 |

Before the test: put the SIM in a phone once, check it can call and text, and **turn off its SIM PIN**.
