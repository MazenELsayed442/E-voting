from PIL import Image, ImageDraw, ImageFont
import os

# Create a new image with a white background
width = 400
height = 400
background_color = (240, 240, 240)
img = Image.new('RGB', (width, height), background_color)

# Get a drawing context
draw = ImageDraw.Draw(img)

# Draw a rectangle border
border_color = (200, 200, 200)
draw.rectangle([(0, 0), (width-1, height-1)], outline=border_color, width=2)

# Draw a placeholder icon (simple camera icon)
icon_color = (180, 180, 180)
margin = 100
draw.rectangle([(margin, margin), (width-margin, height-margin)], outline=icon_color, width=4)
draw.ellipse([(width//2-50, height//2-50), (width//2+50, height//2+50)], outline=icon_color, width=4)

# Save the image
os.makedirs('voting/static/images', exist_ok=True)
img.save('voting/static/images/placeholder.png') 