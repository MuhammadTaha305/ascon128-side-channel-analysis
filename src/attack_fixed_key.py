import numpy as np
import h5py
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.utils import to_categorical
import matplotlib.pyplot as plt

def load_dataset(filename):
    with h5py.File(filename, 'r') as f:
        pt = f['profiling_traces'][:]
        pl = f['profiling_labels'][:]
        at = f['attack_traces'][:]
        al = f['attack_labels'][:]
    return pt, pl, at, al

def build_model(input_dim, num_classes):
    model = Sequential([
        Dense(256, activation='relu', input_shape=(input_dim,)),
        BatchNormalization(),
        Dropout(0.3),
        Dense(128, activation='relu'),
        BatchNormalization(),
        Dropout(0.3),
        Dense(64, activation='relu'),
        Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model

def key_rank_analysis(model, attack_traces, true_labels, n_experiments=10):
    ranks = []
    for _ in range(n_experiments):
        idx = np.random.choice(len(attack_traces), 100, replace=False)
        preds = model.predict(attack_traces[idx], verbose=0)
        avg_pred = np.mean(preds, axis=0)
        sorted_classes = np.argsort(avg_pred)[::-1]
        true_class = true_labels[idx[0]]
        rank = np.where(sorted_classes == true_class)[0][0]
        ranks.append(rank)
    return np.mean(ranks)

pt, pl, at, al = load_dataset("fixed_key_traces.h5")

num_classes = int(pl.max()) + 1
pl_cat = to_categorical(pl, num_classes)
al_cat = to_categorical(al, num_classes)

model = build_model(pt.shape[1], num_classes)

history = model.fit(
    pt, pl_cat,
    epochs=50,
    batch_size=256,
    validation_split=0.1,
    verbose=1
)

loss, acc = model.evaluate(at, al_cat, verbose=0)
print(f"\nAttack Accuracy: {acc*100:.2f}%")

avg_rank = key_rank_analysis(model, at, al)
print(f"Average Key Rank: {avg_rank:.2f}")

model.save("model_fixed_key.h5")

plt.figure(figsize=(12,4))
plt.subplot(1,2,1)
plt.plot(history.history['accuracy'], label='Train')
plt.plot(history.history['val_accuracy'], label='Val')
plt.title('Fixed Key - Accuracy')
plt.xlabel('Epoch'); plt.ylabel('Accuracy'); plt.legend()
plt.subplot(1,2,2)
plt.plot(history.history['loss'], label='Train')
plt.plot(history.history['val_loss'], label='Val')
plt.title('Fixed Key - Loss')
plt.xlabel('Epoch'); plt.ylabel('Loss'); plt.legend()
plt.tight_layout()
plt.savefig("fixed_key_training.png", dpi=150)
