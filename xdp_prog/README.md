README.md
# Run code
1. In xdp-program/xdp_prog, gen header file. Model in /home/haipt/security_paper/rf. Model name in format rf_{num tree}_{max leavec}.pkl
```
python3 rf2qs.py --model ~/security_paper/rf/rf_100_16_model.pkl
```
2. Rebuild
```
make
```
# Measure
1. Number instruction of jited code: total instuction and jump instruction
```
bpftool prog dump jited id <prog-id>
```
2. CPU usage: total, cpu to run detector, cpu to update map
```
perf
```
3. Size of map to save model
```
bpftool map show
```