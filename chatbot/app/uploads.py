import hashlib
import io
from pathlib import Path
import warnings
from PIL import Image,ImageOps,UnidentifiedImageError
from .store import identifier

Image.MAX_IMAGE_PIXELS=20_000_000

class ImageUploads:
    def __init__(self,settings,store):
        self.store=store;self.directory=settings.data_dir/'uploads';self.directory.mkdir(exist_ok=True)
    def save(self,file):
        raw=file.stream.read(8_000_001)
        if not raw or len(raw)>8_000_000:raise ValueError('Image must be nonempty and at most 8 MB')
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error',Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(raw)) as probe:
                    original_format=probe.format
                    if original_format not in ('PNG','JPEG','WEBP'):raise ValueError('Upload PNG, JPEG or WebP; SVG and animated formats are not accepted')
                    if getattr(probe,'n_frames',1)!=1:raise ValueError('Animated images are not accepted')
                    probe.verify()
                with Image.open(io.BytesIO(raw)) as source:
                    width,height=source.size
                    if width*height>20_000_000:raise ValueError('Image exceeds 20 megapixels')
                    preview=ImageOps.exif_transpose(source).convert('RGB')
                    preview.thumbnail((2048,2048))
                    output=io.BytesIO();preview.save(output,format='JPEG',quality=90)
        except (UnidentifiedImageError,OSError,Image.DecompressionBombError,Image.DecompressionBombWarning):
            raise ValueError('Invalid image or unsafe dimensions') from None
        key=identifier();original=self.directory/(key+'.original');dest=self.directory/(key+'.jpg')
        original.write_bytes(raw);dest.write_bytes(output.getvalue())
        metadata={'image_id':key,'format':original_format,'width':width,'height':height,'original_sha256':hashlib.sha256(raw).hexdigest(),'preview_sha256':hashlib.sha256(output.getvalue()).hexdigest(),'preview_width':preview.width,'preview_height':preview.height,'note':'Original retained privately; model receives resized JPEG with metadata removed.'}
        self.store.upload(key,dest,original,metadata)
        return {'id':key,'url':'/api/images/'+key,'metadata':metadata}
