import numpy as np
import h5py
import matplotlib.pyplot as plt
import lief
from rainbow.devices import rainbow_stm32f215
from rainbow import TraceConfig, HammingWeight

def get_hw(val):
    return bin(int(val)).count('1')

def ascon_sbox(x):
    x0, x1, x2, x3, x4 = [(x >> (64*i)) & 0xFFFFFFFFFFFFFFFF for i in range(5)]
    x0 ^= x4; x4 ^= x3; x2 ^= x1
    t = [~xi & 0xFFFFFFFFFFFFFFFF for xi in [x0,x1,x2,x3,x4]]
    t[0] &= x1; t[1] &= x2; t[2] &= x3; t[3] &= x4; t[4] &= x0
    x0 ^= t[1]; x1 ^= t[2]; x2 ^= t[3]; x3 ^= t[4]; x4 ^= t[0]
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = (~x2) & 0xFFFFFFFFFFFFFFFF
    return x0

def compute_target(key_byte, nonce_byte):
    state = 0x80400c0600000000 ^ (int(key_byte) << 56) ^ int(nonce_byte)
    return get_hw((ascon_sbox(state)) & 0xFF)

def generate_datasets():
    print("Parsing ELF binary to locate memory addresses...")
    binary = lief.parse("ascon128.elf")
    key_addr = binary.get_symbol("key").value
    nonce_addr = binary.get_symbol("nonce").value
    main_addr = binary.get_symbol("main").value

    print("Loading binary into Rainbow Cortex-M3 Emulator...")
    emu = rainbow_stm32f215(trace_config=TraceConfig(register=HammingWeight()))
    emu.load('ascon128.elf', typ='.elf')
    
    fixed_key = np.array([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                          0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f], dtype=np.uint8)
    
    fk_traces, fk_labels = [], []
    vk_traces, vk_labels = [], []
    used_keys = set()
    
    print("Generating Fixed-Key Dataset (this may take a few minutes)...")
    for i in range(6000):
        if i % 1000 == 0 and i != 0: 
            print(f"  [{i}/6000] traces captured...")
            
        nonce = np.random.randint(0, 256, 16, dtype=np.uint8)
        
        emu.reset()
        emu[key_addr] = bytes(fixed_key)
        emu[nonce_addr] = bytes(nonce)
        
        emu.start(main_addr | 1, 0, count=500)
        
        trace = np.array([event['register'] for event in emu.trace if 'register' in event], dtype=np.float32)
        trace += np.random.normal(0, 0.5, len(trace)) 
        
        if len(trace) > 400: trace = trace[:400]
        else: trace = np.pad(trace, (0, max(0, 400 - len(trace))))
        
        fk_traces.append(trace)
        fk_labels.append(compute_target(fixed_key[0], nonce[0]))

    print("Generating Variable-Key Dataset...")
    for i in range(6000):
        if i % 1000 == 0 and i != 0: 
            print(f"  [{i}/6000] traces captured...")
            
        while True:
            vk_key = np.random.randint(0, 256, 16, dtype=np.uint8)
            if tuple(vk_key) not in used_keys:
                used_keys.add(tuple(vk_key))
                break
                
        nonce = np.random.randint(0, 256, 16, dtype=np.uint8)
        
        emu.reset()
        emu[key_addr] = bytes(vk_key)
        emu[nonce_addr] = bytes(nonce)
        
        emu.start(main_addr | 1, 0, count=500)
        
        trace = np.array([event['register'] for event in emu.trace if 'register' in event], dtype=np.float32)
        trace += np.random.normal(0, 0.5, len(trace))
        
        if len(trace) > 400: trace = trace[:400]
        else: trace = np.pad(trace, (0, max(0, 400 - len(trace))))
        
        vk_traces.append(trace)
        vk_labels.append(compute_target(vk_key[0], nonce[0]))

    print("Saving HDF5 datasets...")
    with h5py.File('fixed_key_traces.h5', 'w') as f:
        f.create_dataset('profiling_traces', data=np.array(fk_traces[:5000]))
        f.create_dataset('profiling_labels', data=np.array(fk_labels[:5000]))
        f.create_dataset('attack_traces', data=np.array(fk_traces[5000:]))
        f.create_dataset('attack_labels', data=np.array(fk_labels[5000:]))

    with h5py.File('variable_key_traces.h5', 'w') as f:
        f.create_dataset('profiling_traces', data=np.array(vk_traces[:5000]))
        f.create_dataset('profiling_labels', data=np.array(vk_labels[:5000]))
        f.create_dataset('attack_traces', data=np.array(vk_traces[5000:]))
        f.create_dataset('attack_labels', data=np.array(vk_labels[5000:]))

    print("Plotting hardware simulation samples...")
    plt.figure(figsize=(12, 6))
    for i in range(10): plt.plot(fk_traces[i], alpha=0.6, label=f"Trace {i+1}")
    plt.title('Rainbow HW Leakage - Fixed Key')
    plt.xlabel('Instruction Count')
    plt.ylabel('Power (HW + noise)')
    plt.legend(loc='upper right', fontsize=6)
    plt.savefig('Fixed_Key_Sample_Power_Traces.png', dpi=150)
    
    plt.figure(figsize=(12, 6))
    for i in range(10): plt.plot(vk_traces[i], alpha=0.6, label=f"Trace {i+1}")
    plt.title('Rainbow HW Leakage - Variable Key')
    plt.xlabel('Instruction Count')
    plt.ylabel('Power (HW + noise)')
    plt.legend(loc='upper right', fontsize=6)
    plt.savefig('Variable_Key_Sample_Power_Traces.png', dpi=150)
    print("Done. Datasets are ready for Phase 4.")

if __name__ == "__main__":
    generate_datasets()
