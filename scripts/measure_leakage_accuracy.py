import sys

ground_truth = "de ad be ef 67 04 3e 1c 2a 2e 4e 86 3d 99 3f ac 1b 8b ce b6 84 f8 2f f9 95 97 08 63 c1 1d f3 ee ab d7 b3 31 20 36 a6 38 a2 14 b3 2f 8b 0f c7 fe 5c f8 67 b2 74 69 b1 4c 33 ae e8 4d ba be ca fe".split(" ")
results = None

with open(str(sys.argv[1])) as f:
    results = [result.split(' ') for result in [line.strip() for line in f.readlines()]]

full = 0
partial = 0
zero = 0
errors = 0
total = 0
burst = 0
no_burst = 0
for result in results:
    full_before, partial_before = full, partial
    for measurement, actual in zip(result, ground_truth):
        total += 1
        if measurement == actual:
            full += 1
        elif measurement == '00':
            zero += 1
        elif measurement[0] == actual[0] or measurement[1] == actual[1]:
            partial += 1
        else:
            errors += 1
    if full_before != full or partial_before != partial:
        burst += 1
    else:
        no_burst += 1


def print_entry(text, variable):
    print(f"{text}: {variable} ({round((variable/total)*100, 2)}%)")

print_entry("Total", total)
print_entry("Full match", full)
print_entry("Partial match", partial)
print_entry("Matches", full + partial)
print_entry("Burst", burst)
print_entry("No burst", no_burst)
print_entry("Zeros", zero)
print_entry("Errors", errors)
print(full, partial, zero, errors, total)

#print(results)
#print(ground_truth)
