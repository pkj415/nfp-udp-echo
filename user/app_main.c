#include <stdio.h>
#include <pthread.h>

#include <driver.h>
#include <memzone.h>
#include <pthread.h>

#include <nfp_rtsym.h>
#include <nfp_cpp.h>
#include <nfp_net_pmd.h>
#include <rte_byteorder.h>

struct __attribute__((__packed__)) ring_meta {
    uint64_t head;
    uint64_t tail;
    uint64_t len;
    uint64_t buffer_full_cnt;
};

#define HEAD_OFF offsetof(struct ring_meta, head)
#define TAIL_OFF offsetof(struct ring_meta, tail)
#define LEN_OFF offsetof(struct ring_meta, len)
#define BUFFER_FULL_CNT_OFF offsetof(struct ring_meta, buffer_full_cnt)

#define RX_META_SYM "i32.me0._rx_meta"
#define TX_META_SYM "i33.me0._tx_meta"
#define TX_DEBUG "i33.me0._debug"
#define RX_DEBUG "i32.me0._debug"
#define DEBUG_SIZE 8192*32

#define START_SYM "_start"

#define UDP_PACKET_SIZE 1280
#define BUF_SIZE 4096

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

extern int nfp_cpp_dev_main(struct rte_pci_device* dev, struct nfp_cpp* cpp);

const struct memzone* mzone_rx;
const struct memzone* mzone_tx;

uint8_t *start_sym;

uint8_t *rx_meta_sym;
uint8_t *tx_meta_sym;
uint8_t *debug_sym;

uint64_t rx_head_virt;
uint64_t tx_tail_virt;
uint64_t rx_buf_start, tx_buf_start, rx_buf_len, tx_buf_len;
uint64_t total_bytes = 0;

static inline uint64_t RD(volatile void *addr)
{
	const volatile uint32_t *p = addr;
	uint32_t low, high;

	low = nn_readl((volatile const void *)(p + 1));
	high = nn_readl((volatile const void *)p);

	return low + ((uint64_t)high << 32);
}

static inline void WR(uint64_t val, volatile void *addr)
{
	nn_writel(val, (volatile char *)addr + 4);
	nn_writel(val >> 32, addr);
}

void *buffer_logger( void *ptr ) {
    int fd;
    if ((fd = open("buffer_log_rx", O_CREAT | O_RDWR, 0666)) == -1) {
        perror("open failed");
    }

    if (ftruncate(fd, BUF_SIZE) != 0) {
        perror("util_create_shmsiszed: ftruncate failed");
        return NULL;
    }

    int ret;
    while(1) {
        sleep(1);
        ret = pwrite(fd, (void*) mzone_rx->addr, BUF_SIZE, 0);
        if(ret < 0) {
            fprintf(stderr, "Failed to log buffer\n");
        }
    }
}

// TODO - Fix this function.
void *tx_debug_log( void *arg ) {
    struct nfp_cpp_area * area;
    struct nfp_cpp* cpp = arg;
    area = (struct nfp_cpp_area* )malloc(sizeof(struct nfp_cpp_area));

    void *tbl = nfp_rtsym_table_read(cpp);
    debug_sym = nfp_rtsym_map(tbl, TX_DEBUG, DEBUG_SIZE, &area);

    int fd, ret;
    uint64_t temp;
    if ((fd = open("tx_debug_log", O_CREAT | O_RDWR, 0666)) == -1) {
        perror("open failed");
    }

    if (ftruncate(fd, DEBUG_SIZE) != 0) {
        perror("util_create_shmsiszed: ftruncate failed");
        return NULL;
    }

    while(1) {
        sleep(1);
        for (int i=0; i<DEBUG_SIZE/8; i++) {
          temp = RD(debug_sym + i*8);
          ret = pwrite(fd, &temp, 8, 8*i);
          if(ret < 0) {
              fprintf(stderr, "Failed to log tx debug area\n");
          }
        }
    }
}

uint64_t copy_rx_tx(uint64_t copy_len, uint64_t tx_head, uint64_t tx_tail) {
    if (tx_tail < tx_head) {
        copy_len = MIN(copy_len, tx_head - tx_tail - 1);
    } else {
        if (tx_head == tx_buf_start)
            copy_len = MIN(copy_len, tx_buf_start + tx_buf_len - tx_tail - 1);
        else
            copy_len = MIN(copy_len, tx_buf_start + tx_buf_len - tx_tail);
    }
    // printf("Copying %ld bytes from rx to tx\n", copy_len);

    memcpy((void*)tx_tail_virt, (void*)rx_head_virt, copy_len);

    tx_tail_virt += copy_len;
    if (tx_tail_virt == mzone_tx->addr + tx_buf_len)
        tx_tail_virt = mzone_tx->addr;

    uint64_t maybe_tx_tail_sym = tx_tail + copy_len;
    tx_tail = (maybe_tx_tail_sym != tx_buf_start + tx_buf_len) ? maybe_tx_tail_sym : tx_buf_start;
    WR(tx_tail, tx_meta_sym + TAIL_OFF);
    return copy_len;
}

void *rx_tx_manage(void *arg) {
    struct nfp_cpp* cpp = arg;
    void *tbl = nfp_rtsym_table_read(cpp);
    long long unsigned tx_buffer_full_cnt = 0;

    struct nfp_cpp_area * areas[8];
    for (int i=0; i<8; i++) {
        areas[i] = (struct nfp_cpp_area* )malloc(sizeof(struct nfp_cpp_area));
    }

    rx_meta_sym = nfp_rtsym_map(tbl, RX_META_SYM, sizeof(struct ring_meta), &areas[0]);
    tx_meta_sym = nfp_rtsym_map(tbl, TX_META_SYM, sizeof(struct ring_meta), &areas[1]);

    // start_sym = nfp_rtsym_map(tbl, START_SYM, 4, &areas[2]);

    WR(mzone_rx->iova, rx_meta_sym + HEAD_OFF);
    WR(mzone_rx->iova, rx_meta_sym + TAIL_OFF);
    WR(BUF_SIZE, rx_meta_sym + LEN_OFF);

    WR(mzone_tx->iova, tx_meta_sym + HEAD_OFF);
    WR(mzone_tx->iova, tx_meta_sym + TAIL_OFF);
    WR(BUF_SIZE, tx_meta_sym + LEN_OFF);

    sleep(2);

    printf("RX_HEAD=0x%" PRIx64 "\n", RD(rx_meta_sym + HEAD_OFF));
    printf("RX_TAIL=0x%" PRIx64 "\n", RD(rx_meta_sym + TAIL_OFF));
    printf("Len is =0x%" PRIx64 "\n", RD(rx_meta_sym + LEN_OFF));

    printf("TX_HEAD=0x%" PRIx64 "\n", RD(tx_meta_sym + HEAD_OFF));
    printf("TX_TAIL=0x%" PRIx64 "\n", RD(tx_meta_sym + TAIL_OFF));
    printf("Len is =0x%" PRIx64 "\n", RD(tx_meta_sym + LEN_OFF));

    // nn_writel(1, start_sym);

    rx_buf_start = mzone_rx->iova;
    rx_buf_len = BUF_SIZE;
    tx_buf_start = mzone_tx->iova;
    tx_buf_len = BUF_SIZE;

    while (1) {
        uint64_t rx_head = RD(rx_meta_sym + HEAD_OFF);
        uint64_t rx_tail = RD(rx_meta_sym + TAIL_OFF);

        uint64_t tx_head = RD(tx_meta_sym + HEAD_OFF);
        uint64_t tx_tail = RD(tx_meta_sym + TAIL_OFF);

        //printf("RX_HEAD=0x%" PRIx64 "\n", rx_head);
        //printf("RX_TAIL=0x%" PRIx64 "\n", rx_tail);
        //printf("TX_HEAD=0x%" PRIx64 "\n", tx_head);
        //printf("TX_TAIL=0x%" PRIx64 "\n", tx_tail);
        //printf("RX Len is =0x%" PRIx64 "\n", RD(rx_meta_sym + LEN_OFF));
        //printf("TX Len is =0x%" PRIx64 "\n", RD(tx_meta_sym + LEN_OFF));

        //printf("START=0x%" PRIx64 "\n", RD(start_sym));

        if (rx_head != rx_tail) {
            // There is something available for RX.
            uint64_t copy_len;

            if (rx_tail > rx_head) {
                copy_len = rx_tail - rx_head;
            }
            else {
                copy_len = rx_buf_start + rx_buf_len - rx_head;
            }

            if (total_bytes % (1024 * 1024) == 0)
                printf("Total bytes=%ld M, RX full cnt = %ld, TX full cnt = %lld\n", total_bytes/ (1024 * 1024),
                  RD(rx_meta_sym + BUFFER_FULL_CNT_OFF), tx_buffer_full_cnt);

            // Copy copy_len of data from rx to tx buffer for echoing.
            uint64_t copied_len = copy_rx_tx(copy_len, tx_head, tx_tail);

            //printf("Got packet for RX HEAD=0x%" PRIx64 " TAIL=0x%" PRIx64 "\n", rx_head, rx_tail);
            //printf("TX_HEAD=0x%" PRIx64 "\n", tx_head);
            //printf("TX_TAIL=0x%" PRIx64 "\n", tx_tail);
            //printf("Copy len=%ld, Copied len=%ld, Total bytes=%ld\n", copy_len, copied_len, total_bytes);
            //printf("\n");

            if (copied_len == 0)
                tx_buffer_full_cnt += 1;

            total_bytes += copied_len;
            uint64_t maybe_rx_head_sym = rx_head + copied_len;
            maybe_rx_head_sym = maybe_rx_head_sym != rx_buf_start + rx_buf_len ? maybe_rx_head_sym: rx_buf_start;

            WR(maybe_rx_head_sym, rx_meta_sym + HEAD_OFF);

            rx_head_virt += copied_len;
            memset((void *)rx_head_virt, 0, copied_len);

            if (rx_head_virt == mzone_rx->addr + rx_buf_len) {
                rx_head_virt = mzone_rx->addr;
            }
        }
    }
    return NULL;
}

int main(int argc, char* argv[])
{
    pthread_t buf_logger, tx_debug_logger;
    pthread_t rx_tx_manager;
    struct rte_pci_device* dev;
    int ret;

    memzone_init();
    mzone_rx = memzone_reserve(BUF_SIZE);
    mzone_tx = memzone_reserve(BUF_SIZE);

    char temp_udp_pack[256];
    FILE *fileptr = fopen("udp_pkt.pcap", "rb");
    fseek(fileptr, 0, SEEK_END);
    int filelen = ftell(fileptr);
    rewind(fileptr);
    fread(temp_udp_pack, filelen, 1, fileptr);

    // TODO - Check the maximum buffer size that can be allocated contiguously.
    printf("Physical address RX start - 0x%" PRIx64 ", end - 0x%" PRIx64 ", BUF_SIZE=%d\n", mzone_rx->iova, mzone_rx->iova + BUF_SIZE, BUF_SIZE);
    printf("Physical address TX start - 0x%" PRIx64 ", end - 0x%" PRIx64 ", BUF_SIZE=%d\n", mzone_tx->iova, mzone_tx->iova + BUF_SIZE, BUF_SIZE);
    printf("Physical from Virtual address RX start - 0x%" PRIx64 ", end - 0x%" PRIx64 ", BUF_SIZE=%d\n", mem_virt2phy((void*)mzone_rx->addr), mem_virt2phy((void*)(mzone_rx->addr + BUF_SIZE)), BUF_SIZE);

    memset((void *)mzone_rx->addr, 0, BUF_SIZE);
    memset((void *)mzone_tx->addr, 0, BUF_SIZE);

    rx_head_virt = mzone_rx->addr;
    tx_tail_virt = mzone_tx->addr;
    rx_buf_len = BUF_SIZE;
    tx_buf_len = BUF_SIZE;

    // This is a packet that is captured by tshark on kitten1, can be used to quickly test a packet send from TX firmware.
    //unsigned char packet[64] = {0x55, 0x44, 0x33, 0x22,
    //    0x22, 0x11, 0x77, 0x66,
    //    0x66, 0x55, 0x44, 0x33,
    //    0x00, 0x45, 0x00, 0x08,
    //    0x01, 0x00, 0x32, 0x00,
    //    0x11, 0x40, 0x00, 0x00,
    //    0x00, 0x0a, 0x56, 0x66,
    //    0x00, 0x0a, 0x01, 0x00,
    //    0xb8, 0x0b, 0x64, 0x00,
    //    0x1e, 0x00, 0xa0, 0x0f,
    //    0x01, 0x00, 0x7c, 0x61,
    //    0x05, 0x04, 0x03, 0x02,
    //    0x09, 0x08, 0x07, 0x06,
    //    0x0d, 0x0c, 0x0b, 0x0a,
    //    0x11, 0x10, 0x0f, 0x0e,
    //    0x15, 0x14, 0x13, 0x12};
    //memcpy(tx_tail_virt, packet, 80);

    pthread_create( &buf_logger, NULL, buffer_logger, NULL);

    dev = pci_scan();
    if (!dev)
    {
        fprintf(stderr, "Cannot find Netronome NIC\n");
        return 0;
    }

    struct nfp_cpp* cpp;
    ret = pci_probe(dev, &cpp);
    if (ret)
    {
        fprintf(stderr, "Probe unsuccessful\n");
        return 0;
    }

    pthread_create(&rx_tx_manager, NULL, rx_tx_manage, cpp);
    // pthread_create(&tx_debug_logger, NULL, tx_debug_log, cpp);

    // nfp_cpp_dev_main(dev, cpp);

    fprintf(stderr, "Exit CPP handler\n");

    while (1) {
        sleep(1);
    }

    return 0;
}
