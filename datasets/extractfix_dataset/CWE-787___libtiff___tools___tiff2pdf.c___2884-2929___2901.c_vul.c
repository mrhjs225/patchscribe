		if(t2p->tiff_compression == COMPRESSION_JPEG){
			unsigned char table_end[2];
			uint32 count = 0;
			buffer= (unsigned char*) _TIFFmalloc(t2p->tiff_datasize); // t2p->tiff_datasize is 2 in this case.
			if(buffer==NULL){
				TIFFError(TIFF2PDF_MODULE, 
					"Can't allocate " TIFF_SIZE_FORMAT " bytes of memory "
                                        "for t2p_readwrite_pdf_image_tile, %s", 
                                          (TIFF_SIZE_T) t2p->tiff_datasize, 
					TIFFFileName(input));
				t2p->t2p_error = T2P_ERR_ERROR;
				return(0);
			}
			if(TIFFGetField(input, TIFFTAG_JPEGTABLES, &count, &jpt) != 0) {
				if (count >= 4) {
                                        int retTIFFReadRawTile; 
                    /* Ignore EOI marker of JpegTables */
					_TIFFmemcpy(buffer, jpt, count - 2);
					bufferoffset += count - 2;
                    /* Store last 2 bytes of the JpegTables */
					table_end[0] = buffer[bufferoffset-2];
					table_end[1] = buffer[bufferoffset-1];
					xuint32 = bufferoffset;
                                        bufferoffset -= 2;
                                        retTIFFReadRawTile= TIFFReadRawTile(
						input, 
						tile, 
						(tdata_t) &(((unsigned char*)buffer)[bufferoffset]), 
						-1);
                                        if( retTIFFReadRawTile < 0 )
                                        {
                                            _TIFFfree(buffer);
                                            t2p->t2p_error = T2P_ERR_ERROR;
                                            return(0);
                                        }
					bufferoffset += retTIFFReadRawTile;
                    /* Overwrite SOI marker of image scan with previously */
                    /* saved end of JpegTables */
					buffer[xuint32-2]=table_end[0];
					buffer[xuint32-1]=table_end[1];
				}
			}
			t2pWriteFile(output, (tdata_t) buffer, bufferoffset);
			_TIFFfree(buffer);
			return(bufferoffset);
		}
