import torch
import numpy as np
from pathlib import Path

def get_all_files(directory):
    path = Path(directory)
    file_list = [str(file) for file in path.rglob('*') if file.is_file()]
    return file_list


# directory = 'D:\\AION_EMNIST_BYCLASS\\results\\Revision_1'
directory = './FL_Backdoor_CV/results'

all_files = get_all_files(directory)


unwanted_string = ".txt"

for s in all_files[:]:
    if unwanted_string in s:
        all_files.remove(s)

for file_path in all_files:
    model_data = torch.load(file_path, weights_only=False)
    
    ASR = np.array(model_data['poison_accuracy'])
    TER = 1 - np.array(model_data['accuracy'])
    max_index = np.argmax(ASR)

    model_data['ASR'] = np.max(ASR)
    model_data['TER'] = min([TER[i] for i, value in enumerate(ASR) if value == model_data['ASR']])

    parts = file_path.split("\\")[-1]
    dataset = parts.split("_")[0]
    poison_ratio = float(parts.split("_")[1]) / 100
    method = parts.split("_")[5]

    print("{}, {}, poison_ratio: {:.2f}, ASR: {:.3f}, TER: {:.3f}" \
          .format(method, dataset, poison_ratio, model_data['ASR'] * 100, model_data['TER'] * 100))

    # print(f"ASR: {model_data['ASR']}")
    # print(f"TER: {model_data['TER']}")
