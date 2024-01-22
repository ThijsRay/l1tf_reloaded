import matplotlib.pyplot as plt

hit = None
miss = None

with open("results.txt") as f:
    lines = [line.strip().split(" ")[2:] for line in f.readlines()]
    lines = [[int(x) for x in line] for line in lines]
    
    hit = [line[0] for line in lines if line[0] < 2000]
    miss = [line[1] for line in lines if line[1] < 2000]


plt.hist([hit, miss])
plt.show()
