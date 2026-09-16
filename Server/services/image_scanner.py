from PIL import Image
import io

class ImageScanner:
    async def scan(self, file_content: bytes, filename: str) -> dict:
        try:
            img = Image.open(io.BytesIO(file_content))
            
            # Basic checks
            results = {
                "is_clean": True,
                "filename": filename,
                "format": img.format,
                "size": img.size,
                "mode": img.mode,
                "scanner": "Image Scanner"
            }
            
            # Check for suspicious metadata
            exif_data = img.getexif() if hasattr(img, 'getexif') else {}
            if exif_data:
                results["exif_found"] = True
                results["exif_tags_count"] = len(exif_data)
            
            # Advanced steganography detection (LSB analysis)
            try:
                # Store original mode for reporting
                original_mode = img.mode
                
                # Convert to RGB for consistent analysis
                if img.mode in ('RGBA', 'LA', 'P', 'L'):
                    img = img.convert('RGB')
                
                pixels = list(img.getdata())
                
                # Sample more pixels for better accuracy
                sample_size = min(5000, len(pixels))
                sampled_pixels = pixels[:sample_size]
                
                # Check LSB of all RGB channels
                lsb_r = [p[0] & 1 for p in sampled_pixels]
                lsb_g = [p[1] & 1 for p in sampled_pixels]
                lsb_b = [p[2] & 1 for p in sampled_pixels]
                
                ratio_r = sum(lsb_r) / len(lsb_r) if lsb_r else 0.5
                ratio_g = sum(lsb_g) / len(lsb_g) if lsb_g else 0.5
                ratio_b = sum(lsb_b) / len(lsb_b) if lsb_b else 0.5
                
                avg_ratio = (ratio_r + ratio_g + ratio_b) / 3
                
                # Check for suspicious patterns
                # Natural images: 0.45-0.55 is normal
                # Compressed images: 0.3-0.7 is normal
                # Steganography: Often very close to 0.5 (0.48-0.52) or extreme values
                
                suspicious = False
                confidence = "low"
                
                # Very suspicious: All channels extremely close to 0.5 (typical LSB steganography)
                if all(0.48 <= r <= 0.52 for r in [ratio_r, ratio_g, ratio_b]):
                    suspicious = True
                    confidence = "high"
                # Moderately suspicious: Extreme values in multiple channels
                elif sum(1 for r in [ratio_r, ratio_g, ratio_b] if r < 0.25 or r > 0.75) >= 2:
                    suspicious = True
                    confidence = "medium"
                # Very extreme: All channels at 0 or 1 (likely processing error or solid color)
                elif all(r == 0 or r == 1 for r in [ratio_r, ratio_g, ratio_b]):
                    suspicious = False  # Likely a solid color image or error
                    confidence = "low"
                
                results["steganography_suspected"] = suspicious
                results["is_clean"] = not suspicious
                results["lsb_analysis"] = {
                    "red_channel": round(ratio_r, 3),
                    "green_channel": round(ratio_g, 3),
                    "blue_channel": round(ratio_b, 3),
                    "average": round(avg_ratio, 3),
                    "confidence": confidence
                }
                
                if suspicious:
                    results["warning"] = f"Steganography suspected with {confidence} confidence"
                
            except Exception as e:
                results["steganography_check"] = f"failed: {str(e)}"
            
            return results
            
        except Exception as e:
            return {
                "is_clean": None,
                "error": str(e),
                "scanner": "Image Scanner"
            }
