# Deepfake Detection using Biometric Face Recognition

**Full project and code:** [github.com/CryptoL1nx/deepfake-detection-biometrics](https://github.com/CryptoL1nx/deepfake-detection-biometrics)

## Summary
Deepfake detection system built around biometric face verification rather than visual artifact detection. Uses a pretrained ArcFace model (ResNet-50 backbone) to extract facial embeddings and flags deepfakes by measuring identity mismatch via cosine similarity, without ever training on fake data.

**Key results:**
- 100% detection accuracy on FaceForensics++ FaceSwap deepfakes
- AUC = 0.918 on LFW face verification
- Zero false positives at the chosen decision threshold

**Course context:** CS 599 Biometrics, Boston University Metropolitan College — final project.

![Results](https://github.com/CryptoL1nx/deepfake-detection-biometrics/raw/main/results_analysis.png)
