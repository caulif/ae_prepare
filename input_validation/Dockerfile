FROM pytorch/pytorch:2.2.1-cuda11.8-cudnn8-runtime

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir torch==2.4.0+cu124 torchvision==0.19.0+cu124 torchaudio==2.4.0+cu124 \
    --index-url https://download.pytorch.org/whl/cu124
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "./FL_Backdoor_CV/roles/autorun.py"]
