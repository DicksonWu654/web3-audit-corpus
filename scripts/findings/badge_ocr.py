"""Read Zokyo white risk/status strips separately from dark page bodies.

Poppler PPM pixels locate wide white strips. Tesseract reads each strip plus
its title. A recovered badge is inserted only beside an independently matching
existing title, preserving the page's existing text and risk badges.
"""
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
import re
import subprocess
import tempfile
from common import ROOT
from extract import tool,tool_environment
from layout_support import RISK,STATUS,visible


def ppm(data):
    pos=0;tokens=[]
    while len(tokens)<4:
        while data[pos:pos+1].isspace():pos+=1
        if data[pos:pos+1]==b'#':pos=data.index(b'\n',pos)+1;continue
        end=pos
        while not data[end:end+1].isspace():end+=1
        tokens.append(data[pos:end]);pos=end
    if tokens[0]!=b'P6' or tokens[3]!=b'255':raise ValueError('Unsupported PPM')
    return int(tokens[1]),int(tokens[2]),data[pos+1:]


def key(text):return re.sub(r'[^a-z0-9]','',visible(text).casefold())


def recover(path,number,before):
    with tempfile.TemporaryDirectory(prefix='p4d-badge-') as tmp:
        prefix=Path(tmp)/'page'
        subprocess.run([tool('pdftoppm',ROOT),'-f',str(number),'-l',str(number),'-r','160','-singlefile',str(path),str(prefix)],env=tool_environment(ROOT),capture_output=True,timeout=120,check=True)
        w,h,data=ppm(prefix.with_suffix('.ppm').read_bytes())
        if len(data)!=w*h*3:raise ValueError('PPM size mismatch')
        active=[]
        for y in range(h):
            sample=[data[(y*w+x)*3:(y*w+x)*3+3] for x in range(w//10,9*w//10,max(1,w//100))]
            white=sum(min(pixel)>220 for pixel in sample)/len(sample)
            if white>.78:active.append(y)
        bands=[]
        for y in active:
            if bands and y==bands[-1][-1]+1:bands[-1].append(y)
            else:bands.append([y])
        # All-white documents have no dark/white card layout.
        bands=[b for b in bands if 15<=len(b)<=160 and b[0]<h*.85]
        lines=before.splitlines(keepends=True);offsets=[];offset=0
        for line in lines:offsets.append(offset);offset+=len(line)
        inserts=[];receipts=[]
        for i,band in enumerate(bands):
            x0=w//15;x1=19*w//20;y0=max(0,band[0]-3);y1=min(h,band[-1]+100)
            pixels=b''.join(data[(y*w+x0)*3:(y*w+x1)*3] for y in range(y0,y1))
            crop=Path(tmp)/f'badge-{i}.ppm';crop.write_bytes(f'P6\n{x1-x0} {y1-y0}\n255\n'.encode()+pixels)
            result=subprocess.run([tool('tesseract',ROOT),str(crop),'stdout','-l','eng','--psm','6'],env=tool_environment(ROOT),capture_output=True,timeout=60,check=True)
            strip_end=band[-1]+1
            strip_right=min(x1,3*w//5)
            strip_pixels=b''.join(data[(y*w+x0)*3:(y*w+strip_right)*3] for y in range(band[0],strip_end))
            strip_pixels=bytes(0 if b<235 else 255 for b in strip_pixels)
            strip=Path(tmp)/f'strip-{i}.ppm';strip.write_bytes(f'P6\n{strip_right-x0} {strip_end-band[0]}\n255\n'.encode()+strip_pixels)
            header=subprocess.run([tool('tesseract',ROOT),str(strip),'stdout','-l','eng','--psm','7'],env=tool_environment(ROOT),capture_output=True,timeout=60,check=True)
            text=header.stdout.decode()+result.stdout.decode();parts=[x.strip() for x in text.splitlines() if x.strip()]
            badge=next((x for x in parts if re.search(r'\b'+RISK+r'\s*[-–]\s*\d+',x,re.I)),None)
            if not badge:
                receipts.append({'accepted':False,'reason':'no_badge','ocr_text':text,'pixel_box':[x0,y0,x1,y1]});continue
            m=re.search(r'('+RISK+r')\s*[-–]\s*(\d+(?:\.\d+)*)',badge,re.I)
            pid=m[1]+'-'+m[2]
            source_id=key(pid)
            existing=next((j for j,line in enumerate(lines) if re.search(RISK+r'\s*[-–]\s*\d+',visible(line),re.I) and source_id==key(re.search(RISK+r'\s*[-–]\s*\d+(?:\.\d+)*',visible(line),re.I)[0]) and re.match(r'^\s*(?:[|7—–]+\s*)?'+RISK+r'\s*[-–]',visible(line),re.I)),None) if any(re.search(RISK+r'\s*[-–]\s*\d+',visible(line),re.I) for line in lines) else None
            if existing is not None:
                status=re.search(r'\b('+STATUS+r')\b',badge,re.I)
                if status and not re.search(STATUS,lines[existing],re.I):
                    end=offsets[existing]+len(lines[existing].rstrip('\r\n'))
                    inserts.append((end,' '+status[1]))
                    receipts.append({'accepted':True,'badge':badge,'status_recovered':True,'insertion_offset':end})
                continue
            title=' '.join(parts[parts.index(badge)+1:])
            if len(key(title))<12:continue
            matches=[(SequenceMatcher(None,key(title),key(line)).ratio(),j) for j,line in enumerate(lines) if len(key(line))>=12]
            score,j=max(matches,default=(0,None))
            receipt={'badge':badge,'title_ocr':title,'title_match_score':round(score,4),'pixel_box':[x0,y0,x1,y1]}
            if score<.65 or j is None:receipt['accepted']=False;receipts.append(receipt);continue
            receipt.update(accepted=True,insertion_offset=offsets[j]);receipts.append(receipt)
            status=re.search(r'\b('+STATUS+r')\b',badge,re.I)
            selected=m[0]+(' '+status[1] if status else '')
            inserts.append((offsets[j],selected+'\n'))
        for offset,text in sorted(set(inserts),reverse=True):before=before[:offset]+text+before[offset:]
        return before,receipts
