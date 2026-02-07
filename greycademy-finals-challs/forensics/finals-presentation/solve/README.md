unzip the pptx, edit `[Content_Types].xml` and `ppt/slideMasters/_rels/slideMaster1.xml.rels` by reverting the two mentions of `slideLayout14.xml` back to `slideLayout13` (which is not referenced anywhere)
zip the folder, rename as pptx and open the file -> slide master to find flag in base64

alternatively, can just open `ppt/slideLayouts/slideLayout13.xml` and yank the base64

decode from b64 back to get flag
