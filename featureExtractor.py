from ml.feature_pipeline import build_feature_frame

# Function to extract features
def featureExtraction(url):
  """Return canonical feature frame shared by training and inference."""
  return build_feature_frame(url)