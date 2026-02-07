import numpy as np
from PIL import Image
import sys
import os
import pickle
import json

def preprocess_image(image_path):
    """
    Load and preprocess an image for model input
    - Convert to grayscale
    - Crop to digit bounding box
    - Resize to 28x28 while maintaining aspect ratio
    - Normalize pixel values
    - Invert colors if needed (MNIST has white digits on black background)
    - Flatten to 784 dimensions for sklearn model
    """
    # Load image
    img = Image.open(image_path).convert('L')  # Convert to grayscale
    img_array = np.array(img)
    
    # Check if we need to invert (MNIST has white digits on black background)
    # If the mean pixel value is > 127, the image is likely white background
    if img_array.mean() > 127:
        img_array = 255 - img_array
    
    # Apply threshold to find digit region
    threshold = np.mean(img_array) + 0.5 * np.std(img_array)
    binary = img_array > threshold
    
    # Find bounding box of the digit
    rows = np.any(binary, axis=1)
    cols = np.any(binary, axis=0)
    
    if rows.any() and cols.any():
        rmin, rmax = np.where(rows)[0][[0, -1]]
        cmin, cmax = np.where(cols)[0][[0, -1]]
        
        # Add padding (10% of the dimension)
        height = rmax - rmin
        width = cmax - cmin
        pad_h = int(height * 0.1)
        pad_w = int(width * 0.1)
        
        rmin = max(0, rmin - pad_h)
        rmax = min(img_array.shape[0], rmax + pad_h)
        cmin = max(0, cmin - pad_w)
        cmax = min(img_array.shape[1], cmax + pad_w)
        
        # Crop to bounding box
        img_array = img_array[rmin:rmax, cmin:cmax]
    
    # Convert back to PIL Image for resizing
    img_cropped = Image.fromarray(img_array.astype(np.uint8))
    
    # Resize to 20x20 first, then center in 28x28 (like MNIST)
    img_resized = img_cropped.resize((20, 20), Image.Resampling.LANCZOS)
    
    # Create 28x28 black canvas and paste resized image in center
    final_img = Image.new('L', (28, 28), 0)
    offset = ((28 - 20) // 2, (28 - 20) // 2)
    final_img.paste(img_resized, offset)
    
    # Convert to numpy array
    img_array = np.array(final_img)
    
    # Normalize to [0, 1]
    img_array = img_array.astype("float32") / 255.0
    
    # Flatten to 784 dimensions (28*28) for sklearn model
    img_flattened = img_array.reshape(1, -1)
    
    return img_flattened, final_img


def main():
    # Load the trained model
    model_path = sys.argv[1]
    
    if not os.path.exists(model_path):
        print(f"Error: Model file '{model_path}' not found!", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loading model from {model_path}...", file=sys.stderr)
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    print("Model loaded successfully!\n", file=sys.stderr)

    img_path = sys.argv[2]
    
    
    if not os.path.exists(img_path):
        print(f"\nWarning: Image '{img_path}' not found.", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Preprocess image
        processed_img, final_img = preprocess_image(img_path)
        
        # Make prediction
        prediction = model.predict(processed_img)[0]
        probabilities = model.predict_proba(processed_img)[0]
        
        predicted_digit = "7" if prediction == 1 else "6"
        confidence = probabilities[1] if prediction == 1 else probabilities[0]
        
        print(f"\nImage: {img_path}", file=sys.stderr)
        print(f"Predicted: {predicted_digit}", file=sys.stderr)
        print(f"Confidence: {confidence:.2%}", file=sys.stderr)
        print(f"Probabilities - 6: {probabilities[0]:.4f}, 7: {probabilities[1]:.4f}", file=sys.stderr)

        # Attempt to save the processed (28x28) image as a thumbnail next to the original
        try:
            thumb_name = os.path.splitext(os.path.basename(img_path))[0] + '_thumb.png'
            # Save thumbnails into a dedicated thumbnails folder next to the session folder
            # If img_path is .../data/<token>/uploads/<file>, thumbnails will be in .../data/<token>/thumbnails/
            thumb_folder = os.path.join(os.path.dirname(os.path.dirname(img_path)), 'thumbnails')
            os.makedirs(thumb_folder, exist_ok=True)
            thumb_path = os.path.join(thumb_folder, thumb_name)
            # final_img is grayscale PIL Image (28x28) from preprocess_image
            final_img.save(thumb_path)
        except Exception as e:
            print(f"Warning: failed to save thumbnail for {img_path}: {e}", file=sys.stderr)
            thumb_name = None

        print(json.dumps({
            'prediction': predicted_digit,
            'confidence': confidence,
            'thumbnail': thumb_name,
            'probabilities': {
                '6': probabilities[0],
                '7': probabilities[1]
            }
        }))

        
    except Exception as e:
        print(f"\nError processing {img_path}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
