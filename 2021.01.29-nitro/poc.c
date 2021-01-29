// Modified from show_nitf.c to illusrate two bugs in the NITF writer

/* =========================================================================
 * This file is part of NITRO
 * =========================================================================
 *
 * (C) Copyright 2004 - 2014, MDA Information Systems LLC
 *
 * NITRO is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, If not,
 * see <http://www.gnu.org/licenses/>.
 *
 */

#include <import/nitf.h>

/*
 *  These macros are just for retrieving the data simply as raw
 *  strings.  They are not very robust, since we dont bother to check
 *  here that your data is printable.  We do not recommend using this
 *  approach within your own program.
 *
 *  Typically, you would use the Field conversion functions
 *  (which are used within the program whenever we are testing
 *  a value).
 */
#define SHOW(X) printf("%s=[%s]\n", #X, ((X==0)?"(nul)":X))
#define SHOW_I(X) printf("%s=[%ld]\n", #X, X)
#define SHOW_LLI(X) printf("%s=[%lld]\n", #X, X)
#define SHOW_LLU(X) printf("%s=[%llu]\n", #X, X)

#define SHOW_RGB(X) \
    printf("%s(R,G,B)=[0x%x,0x%x,0x%x]\n", #X, (short)(X->raw[0]), (short)(X->raw[1]), (short)(X->raw[2]))

#define SHOW_VAL(X) \
    printf("%s=[%.*s]\n", #X, ((X==0)?8:((X->raw==0)?5:(int)X->length)), \
                  ((X==0)?"(nulptr)":((X->raw==0)?"(nul)":X->raw)))



void measureComplexity(nitf_Record* record)
{

    nitf_Error error;
    char str[3];
    NITF_CLEVEL recorded, clevel;
    str[2] = 0;

    recorded = nitf_ComplexityLevel_get(record);

    clevel = nitf_ComplexityLevel_measure(record, &error);

    if ((int)recorded != (int)clevel)
    {
        if (!nitf_ComplexityLevel_toString(clevel, str))
        {
            printf("CLEVEL measurement failed");
            nitf_Error_print(&error, stdout, "Measurement problem");
        }
        printf("Measured CLEVEL differs from recorded: '%s', ", str);
        nitf_ComplexityLevel_toString(recorded, str);
        printf("file: '%s'\n", str);
    }
}

/*
 *  This function dumps a TRE using the TRE enumerator.
 *  The enumerator is used to walk the fields of a TRE in order
 *  when the TRE enumerator is expired it will be set to NULL.
 *
 */
void printTRE(nitf_TRE* tre)
{
    nitf_Error error;
    nitf_Uint32 treLength;
    nitf_TREEnumerator* it = NULL;
    const char* treID = NULL;

    /* This is just so you know how long the TRE is */
    treLength = tre->handler->getCurrentSize(tre, &error);

    /*
     *  This is the name for the description that was selected to field
     *  this TRE by the handler.
     */
    treID = nitf_TRE_getID(tre);

    printf("\n--------------- %s TRE (%d) - (%s) ---------------\n",
           tre->tag, treLength, treID ? treID : "null id");

    /* Now walk the TRE */
    it = nitf_TRE_begin(tre, &error);

    while(it && it->hasNext(&it))
    {
        /* If this isn't set, it should have been an error */
        nitf_Pair* fieldPair = it->next(it, &error);
        if (fieldPair)
        {
            const char* desc = it->getFieldDescription(it, &error);
            printf("%s", fieldPair->key);
            if (desc)
                printf(" (%s)", desc);
            printf(" = [");
            nitf_Field_print((nitf_Field *) fieldPair->data);
            printf("]\n");
        }
        else
            nitf_Error_print(&error, stdout, "Field retrieval error");

    }
    printf("---------------------------------------------\n");
}

/*
 *  This function shows us the best way of walking through
 *  an extension segment (userDefined or extended)
 */
void showExtensions(nitf_Extensions* ext)
{

    /* These let you walk an extensions like a list */
    nitf_ExtensionsIterator iter;
    nitf_ExtensionsIterator end;

    /* Get the beginning pointer */
    iter = nitf_Extensions_begin(ext);

    /* Get the pointer to end */
    end  = nitf_Extensions_end(ext);

    /* Iterations */
    while (nitf_ExtensionsIterator_notEqualTo(&iter, &end) )
    {
        nitf_TRE* tre = nitf_ExtensionsIterator_get(&iter);
        /* Prints a single TRE */
        printTRE( tre );
        /* Don't forget to increment this */
        nitf_ExtensionsIterator_increment(&iter);
    }
}

/*
 *  This function dumps the security header.
 *
 */
void showSecurityGroup(nitf_FileSecurity* securityGroup)
{

    assert( securityGroup );

    SHOW_VAL(securityGroup->classificationSystem);
    SHOW_VAL(securityGroup->codewords);
    SHOW_VAL(securityGroup->controlAndHandling);
    SHOW_VAL(securityGroup->releasingInstructions);
    SHOW_VAL(securityGroup->declassificationType);
    SHOW_VAL(securityGroup->declassificationDate);
    SHOW_VAL(securityGroup->declassificationExemption);
    SHOW_VAL(securityGroup->downgrade);
    SHOW_VAL(securityGroup->downgradeDateTime);
    SHOW_VAL(securityGroup->classificationText);
    SHOW_VAL(securityGroup->classificationAuthorityType);
    SHOW_VAL(securityGroup->classificationAuthority);
    SHOW_VAL(securityGroup->classificationReason);
    SHOW_VAL(securityGroup->securitySourceDate);
    SHOW_VAL(securityGroup->securityControlNumber);
}

/*
 *  The file header contains information that is relevant
 *  to the entire file, including subheader and segment
 *  lengths, file length, header length, and security level
 *  for the file.
 */
void showFileHeader(nitf_Record * record)
{
    unsigned int i;
    nitf_Uint32 num;
    nitf_Error error;
    nitf_Uint32 len;
    nitf_Uint64 dataLen;
    nitf_Uint32 dataLen32;
    nitf_Version fver;
    nitf_FileHeader *header;

    fver = nitf_Record_getVersion(record);

    /* Sanity check */
    assert( record );
    header = record->header;
    assert( header );

    /* Dump the values in order */
    SHOW_VAL(header->fileHeader);
    SHOW_VAL(header->fileVersion);
    SHOW_VAL(header->complianceLevel);
    SHOW_VAL(header->systemType);
    SHOW_VAL(header->originStationID);
    SHOW_VAL(header->fileDateTime);
    SHOW_VAL(header->fileTitle);
    SHOW_VAL(header->classification);

    if (*(header->classification->raw) != 'U')
        showSecurityGroup(header->securityGroup);

    SHOW_VAL(header->messageCopyNum);
    SHOW_VAL(header->messageNumCopies);
    SHOW_VAL(header->encrypted);

    if (IS_NITF21(fver))
        SHOW_RGB(header->backgroundColor);
    SHOW_VAL(header->originatorName);
    SHOW_VAL(header->originatorPhone);
    SHOW_VAL(header->fileLength);
    SHOW_VAL(header->headerLength);

    if (!nitf_Field_get(header->numImages,
                        &num, NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;


    printf("The number of images contained in this file [%lu]\n", num);
    for (i = 0; i < num; i++)
    {

        if (!nitf_Field_get(header->imageInfo[i]->lengthSubheader,
                            &len, NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        if (!nitf_Field_get(header->imageInfo[i]->lengthData,
                            &dataLen,
                            NITF_CONV_INT, NITF_INT64_SZ, &error))
            goto CATCH_ERROR;

        printf("\tThe length of image subheader [%u]: %lu bytes\n",
               i, len);
        printf("\tThe length of the image data: %llu bytes\n\n", dataLen);
    }

    if (!nitf_Field_get(header->numGraphics,
                        &num, NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;


    printf("The number of graphics contained in this file [%ld]\n", num);
    for (i = 0; i < num; i++)
    {

        if (!nitf_Field_get(header->graphicInfo[i]->lengthSubheader,
                            &len, NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        if (!nitf_Field_get(header->graphicInfo[i]->lengthData,
                            &dataLen32,
                            NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        printf("\tThe length of graphic subheader [%u]: %lu bytes\n",
               i, len);
        printf("\tThe length of the graphic data: %lu bytes\n\n",
               dataLen32);
    }

    if (!nitf_Field_get(header->numLabels,
                        &num, NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;

    printf("The number of labels contained in this file [%ld]\n", num);
    for (i = 0; i < num; i++)
    {

        if (!nitf_Field_get(header->labelInfo[i]->lengthSubheader,
                            &len, NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        if (!nitf_Field_get(header->labelInfo[i]->lengthData,
                            &dataLen32,
                            NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;
        printf("\tThe length of label subheader [%u]: %lu bytes\n",
               i, len);

        printf("\tThe length of the label data: %lu bytes\n\n",
               dataLen32);
    }

    if (!nitf_Field_get(header->numTexts,
                        &num, NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;

    printf("The number of text sections contained in this file [%ld]\n",
           num);

    for (i = 0; i < num; i++)
    {
        if (!nitf_Field_get(header->textInfo[i]->lengthSubheader,
                            &len, NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        if (!nitf_Field_get(header->textInfo[i]->lengthData,
                            &dataLen32,
                            NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        printf("\tThe length of text subheader [%u]: %lu bytes\n",
               i, len);

        printf("\tThe length of the text data: %lu bytes\n\n",
               dataLen32);
    }

    if (!nitf_Field_get(header->numDataExtensions,
                        &num, NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;

    printf("The number of DES contained in this file [%ld]\n",
           num);

    for (i = 0; i < num; i++)
    {
        if (!nitf_Field_get(header->dataExtensionInfo[i]->lengthSubheader,
                            &len, NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        if (!nitf_Field_get(header->dataExtensionInfo[i]->lengthData,
                            &dataLen32,
                            NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        printf("\tThe length of DES subheader [%u]: %lu bytes\n",
               i, len);
        printf("\tThe length of the DES data: %lu bytes\n\n",
               dataLen32);
    }


    if (!nitf_Field_get(header->numReservedExtensions,
                        &num, NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;

    printf("The number of RES contained in this file [%ld]\n",
           num);

    for (i = 0; i < num; i++)
    {


        if (!nitf_Field_get
                (header->reservedExtensionInfo[i]->lengthSubheader, &len,
                 NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        if (!nitf_Field_get(header->reservedExtensionInfo[i]->lengthData,
                            &dataLen32,
                            NITF_CONV_INT, NITF_INT32_SZ, &error))
            goto CATCH_ERROR;

        printf("\tThe length of RES subheader [%u]: %lu bytes\n",
               i, len);

        printf("\tThe length of the RES data: %lu bytes\n\n",
               dataLen32);
    }

    if (!nitf_Field_get(header->userDefinedHeaderLength, &num,
                        NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;

    printf("The user-defined header length [%ld]\n", num);

    if (header->userDefinedSection)
        showExtensions( header->userDefinedSection );

    if (!nitf_Field_get(header->extendedHeaderLength, &num,
                        NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;

    printf("The extended header length [%ld]\n", num);

    if (header->extendedSection)
        showExtensions( header->extendedSection );

    return;

CATCH_ERROR:
    printf("Error processing\n");
}

/*
 *  Show the image subheader.  This contains information
 *  about a specific segment.  That includes the pixel interleaving,
 *  block info, pixel information and band info.
 *
 */
void showImageSubheader(nitf_ImageSubheader * sub)
{
    int q;
    int nbands, xbands;
    nitf_Error error;
    int ncomments;
    nitf_ListIterator iter, end;
    nitf_CornersType cornersType;
    assert( sub );

    if (!nitf_Field_get(sub->numImageComments,
                        &ncomments, NITF_CONV_INT, NITF_INT32_SZ, &error))
    {
        goto CATCH_ERROR;
    }

    printf("image subheader:\n");
    SHOW_VAL(sub->filePartType);
    SHOW_VAL(sub->imageId);
    SHOW_VAL(sub->imageDateAndTime);
    SHOW_VAL(sub->targetId);
    SHOW_VAL(sub->imageTitle);
    SHOW_VAL(sub->imageSecurityClass);

    if (*(sub->imageSecurityClass->raw) != 'U')
        showSecurityGroup(sub->securityGroup);

    SHOW_VAL(sub->encrypted);
    SHOW_VAL(sub->imageSource);
    SHOW_VAL(sub->numRows);
    SHOW_VAL(sub->numCols);
    SHOW_VAL(sub->pixelValueType);
    SHOW_VAL(sub->imageRepresentation);
    SHOW_VAL(sub->imageCategory);
    SHOW_VAL(sub->actualBitsPerPixel);
    SHOW_VAL(sub->pixelJustification);
    SHOW_VAL(sub->imageCoordinateSystem);
    SHOW_VAL(sub->cornerCoordinates);

    cornersType = nitf_ImageSubheader_getCornersType(sub);

    if (cornersType == NITF_CORNERS_GEO ||
        cornersType == NITF_CORNERS_DECIMAL)
    {
        double corners[4][2];

        if (!nitf_ImageSubheader_getCornersAsLatLons(sub, corners, &error))
        {
            nitf_Error_print(&error, stdout, "Warning: Corners appear to be invalid!");
        }
        else
        {
            printf("(0,0): (%f, %f)\n", corners[0][0], corners[0][1]);
            printf("(0,C): (%f, %f)\n", corners[1][0], corners[1][1]);
            printf("(R,C): (%f, %f)\n", corners[2][0], corners[2][1]);
            printf("(R,0): (%f, %f)\n", corners[3][0], corners[3][1]);

        }

    }



    SHOW_VAL(sub->numImageComments);

    iter = nitf_List_begin(sub->imageComments);
    end = nitf_List_end(sub->imageComments);
    while (nitf_ListIterator_notEqualTo(&iter, &end))
    {
        nitf_Field* commentField = (nitf_Field*) nitf_ListIterator_get(&iter);
        SHOW_VAL(commentField);
        nitf_ListIterator_increment(&iter);
    }

    SHOW_VAL(sub->imageCompression);
    SHOW_VAL(sub->compressionRate);

    SHOW_VAL(sub->numImageBands);
    SHOW_VAL(sub->numMultispectralImageBands);

    if (!nitf_Field_get(sub->numImageBands, &nbands,
                        NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;


    if (!nitf_Field_get(sub->numMultispectralImageBands, &xbands,
                        NITF_CONV_INT, NITF_INT32_SZ, &error))
        goto CATCH_ERROR;


    nbands += xbands;
    for (q = 0; q < nbands; q++)
    {
        SHOW_VAL(sub->bandInfo[q]->representation);
        SHOW_VAL(sub->bandInfo[q]->subcategory);
        SHOW_VAL(sub->bandInfo[q]->imageFilterCondition);
        SHOW_VAL(sub->bandInfo[q]->imageFilterCode);
        SHOW_VAL(sub->bandInfo[q]->numLUTs);
        SHOW_VAL(sub->bandInfo[q]->bandEntriesPerLUT);
    }

    /*  Skip band stuff for now  */
    SHOW_VAL(sub->imageSyncCode);
    SHOW_VAL(sub->imageMode);
    SHOW_VAL(sub->numBlocksPerRow);
    SHOW_VAL(sub->numBlocksPerCol);
    SHOW_VAL(sub->numPixelsPerHorizBlock);
    SHOW_VAL(sub->numPixelsPerVertBlock);
    SHOW_VAL(sub->numBitsPerPixel);
    SHOW_VAL(sub->imageDisplayLevel);
    SHOW_VAL(sub->imageAttachmentLevel);
    SHOW_VAL(sub->imageLocation);
    SHOW_VAL(sub->imageMagnification);

    SHOW_VAL(sub->userDefinedImageDataLength);
    SHOW_VAL(sub->userDefinedOverflow);

    if (sub->userDefinedSection)
        showExtensions( sub->userDefinedSection );

    SHOW_VAL(sub->extendedHeaderLength);
    SHOW_VAL(sub->extendedHeaderOverflow);

    if (sub->extendedSection)
        showExtensions( sub->extendedSection );
    return;

CATCH_ERROR:
    printf("Error processing\n");

}

/*
 *  This section is for vector graphics.  Currently
 *  this will be CGM 1.0 (there is a spec for NITF CGM,
 *  but the original CGM 1.0 spec is out-of-print.
 *
 *  Note that this function does not dump the binary CGM
 *  You can use the NITRO CGM library to read the CGM data
 *  from the NITF (and dump it)
 */
void showGraphicSubheader(nitf_GraphicSubheader * sub)
{
    assert( sub );

    printf("graphic subheader:\n");
    SHOW_VAL(sub->filePartType);
    SHOW_VAL(sub->graphicID);
    SHOW_VAL(sub->name);
    SHOW_VAL(sub->securityClass);

    if (*(sub->securityClass->raw) != 'U')
        showSecurityGroup(sub->securityGroup);

    SHOW_VAL(sub->encrypted);
    SHOW_VAL(sub->stype);
    SHOW_VAL(sub->res1);
    SHOW_VAL(sub->displayLevel);
    SHOW_VAL(sub->attachmentLevel);
    SHOW_VAL(sub->location);
    SHOW_VAL(sub->bound1Loc);
    SHOW_VAL(sub->color);
    SHOW_VAL(sub->bound2Loc);
    SHOW_VAL(sub->res2);
    SHOW_VAL(sub->extendedHeaderLength);
    SHOW_VAL(sub->extendedHeaderOverflow);
    if (sub->extendedSection)
        showExtensions( sub->extendedSection );
}

/*
 *  Label was superceded for NITF 2.1
 *
 */
void showLabelSubheader(nitf_LabelSubheader * sub)
{
    assert( sub );
    printf("label subheader\n");
    SHOW_VAL(sub->filePartType);
    SHOW_VAL(sub->labelID);
    SHOW_VAL(sub->securityClass);

    if (*(sub->securityClass->raw) != 'U')
        showSecurityGroup(sub->securityGroup);

    SHOW_VAL(sub->encrypted);
    SHOW_VAL(sub->fontStyle);
    SHOW_VAL(sub->cellWidth);
    SHOW_VAL(sub->cellHeight);
    SHOW_VAL(sub->displayLevel);
    SHOW_VAL(sub->attachmentLevel);
    SHOW_VAL(sub->locationRow);
    SHOW_VAL(sub->locationColumn);
    SHOW_RGB(sub->textColor);
    SHOW_RGB(sub->backgroundColor);
    SHOW_VAL(sub->extendedHeaderLength);
    SHOW_VAL(sub->extendedHeaderOverflow);
    if (sub->extendedSection)
        showExtensions( sub->extendedSection );
}

/*
 *  This section contains raw text data.  You can put
 *  lots of stuff in here but most people never do.
 *
 *  Note that XML data is usually not contained in this section
 *  even though that might have made more sense.  XML data is
 *  typically found in the DES segment
 */
void showTextSubheader(nitf_TextSubheader * sub)
{
    assert( sub );

    printf("text subheader\n");
    SHOW_VAL(sub->filePartType);
    SHOW_VAL(sub->textID);
    SHOW_VAL(sub->attachmentLevel);
    SHOW_VAL(sub->dateTime);
    SHOW_VAL(sub->title);
    SHOW_VAL(sub->securityClass);

    if (*(sub->securityClass->raw) != 'U')
        showSecurityGroup(sub->securityGroup);

    SHOW_VAL(sub->encrypted);
    SHOW_VAL(sub->format);
    SHOW_VAL(sub->extendedHeaderLength);
    SHOW_VAL(sub->extendedHeaderOverflow);
    if (sub->extendedSection)
        showExtensions(sub->extendedSection);
}
/*
 *  This section is for dumping the Data Extension Segment (DES)
 *  subheader.  It can hold up to 1GB worth of data, so its big
 *  enough for most things.  People stuff all kinds of things in
 *  the DESDATA block including
 *
 *  - TRE overflow:
 *      When a TRE is too big for the section its in.  In other words,
 *      if populating it properly would overflow the segment, it is
 *      dumped into the TRE overflow segment.
 *
 *      This is kind of a pain, and so NITRO 2.0 has functions to
 *      split this up for you, or merge it back into the header where it
 *      would go if it wasnt too big (see nitf_Record_mergeTREs() and
 *      nitf_Record_unmergeTREs).
 *
 *      However, by default, we assume that you want the data as it
 *      appeared in the file.  Therefore, when you dump a record, you
 *      might see overflow data
 *
 *  - Text data (especially XML)
 *
 *      XML data is getting more popular, and to make sure that they
 *      dont have to worry about the length of the XML surpassing the
 *      limits of a segment, most people decide to spec. it to go here
 *
 *  - Binary data
 *
 *      Since the DES is the wild west of the NITF, you can put anything
 *      you want here.
 *
 *  Confusingly, the DES subheader has its own little TRE-like
 *  arbitrary key-value params.  In NITRO we treat this as a TRE within
 *  the subheader.
 *
 *  This function prints the DE subheader, the extended TRE described above,
 *  and additionally, if the DESDATA is TRE overflow, we dump those too.
 */
void showDESubheader(nitf_DESubheader * sub)
{
    assert( sub );

    printf("DES subheader\n");
    SHOW_VAL(sub->filePartType);
    SHOW_VAL(sub->typeID);
    SHOW_VAL(sub->version);
    SHOW_VAL(sub->securityClass);

    if (*(sub->securityClass->raw) != 'U')
        showSecurityGroup(sub->securityGroup);

    SHOW_VAL(sub->overflowedHeaderType);
    SHOW_VAL(sub->dataItemOverflowed);
    SHOW_VAL(sub->subheaderFieldsLength);

    /*
     *  This is the user defined parameter section
     *  within the DES.  It contains only BCS-A/N type values
     *  so storing it in a 'TRE' struct is no big deal
     */
    if (sub->subheaderFields)
        printTRE(sub->subheaderFields);

    SHOW_LLU(sub->dataLength);

    /*
     *  NITRO only populates this object if the DESDATA contains
     *  TRE overflow.  Otherwise, you need to use a DEReader to
     *  get at the DESDATA, since it can contain anything.
     *
     *  We wont bother to try and print whatever other things might
     *  have been put in here (e.g, text data or binary blobs)
     */
    if (sub->userDefinedSection)
        showExtensions( sub->userDefinedSection );
}

/*
 *  This section is never really populated
 */
void showRESubheader(nitf_RESubheader * sub)
{
    assert( sub );

    printf("RES subheader\n");
    SHOW_VAL(sub->filePartType);
    SHOW_VAL(sub->typeID);
    SHOW_VAL(sub->version);
    SHOW_VAL(sub->securityClass);

    if (*(sub->securityClass->raw) != 'U')
        showSecurityGroup(sub->securityGroup);

    SHOW_VAL(sub->subheaderFieldsLength);
    SHOW_LLU(sub->dataLength);
}

int main(int argc, char **argv)
{
    /*  Get the error object  */
    nitf_Error error;

    /*  This is the reader object  */
    nitf_Reader *reader;
    nitf_Record *record;

    /*  The IO handle  */
    nitf_IOHandle io;
    int num;

    /*  Check argv and make sure we are happy  */
    if (argc != 2)
    {
        printf("Usage: %s <nitf-file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /*  You should use this function to test that you have a valid NITF */
    if (nitf_Reader_getNITFVersion( argv[1] ) == NITF_VER_UNKNOWN)
    {
        printf("This file does not appear to be a valid NITF\n");
        exit(EXIT_FAILURE);
    }



    /*
     *  Using an IO handle is one valid way to read a NITF in
     *
     *  NITRO 2.5 offers other ways, using the readIO() function
     *  in the Reader
     */
    io = nitf_IOHandle_create(argv[1], NITF_ACCESS_READONLY,
                              NITF_OPEN_EXISTING, &error);
    if (NITF_INVALID_HANDLE(io))
    {
        nitf_Error_print(&error, stdout, "Exiting...");
        exit(EXIT_FAILURE);
    }

    /*  We need to make a reader so we can parse the NITF */
    reader = nitf_Reader_construct(&error);
    if (!reader)
    {
        nitf_Error_print(&error, stdout, "Exiting (1) ...");
        exit(EXIT_FAILURE);
    }

    /*  This parses all header data within the NITF  */
    record = nitf_Reader_read(reader, io, &error);
    if (!record) goto CATCH_ERROR;

    /* Now show the header */
    showFileHeader(record);

    num = nitf_Record_getNumImages(record, &error);

    if (NITF_INVALID_NUM_SEGMENTS( num ) )
        goto CATCH_ERROR;

    /* And now show the image information */
    if (num)
    {
        /*  Walk each image and show  */
        nitf_ListIterator iter = nitf_List_begin(record->images);
        nitf_ListIterator end = nitf_List_end(record->images);

        while (nitf_ListIterator_notEqualTo(&iter, &end))
        {
            nitf_ImageSegment *segment =
                (nitf_ImageSegment *) nitf_ListIterator_get(&iter);
            showImageSubheader(segment->subheader);
            nitf_ListIterator_increment(&iter);
        }
    }
    else
    {
        printf("No image in file!\n");
    }

    num = nitf_Record_getNumGraphics(record, &error);
    if (NITF_INVALID_NUM_SEGMENTS( num ) )
        goto CATCH_ERROR;

    if (num)
    {
        /*  Walk each graphic and show  */
        nitf_ListIterator iter = nitf_List_begin(record->graphics);
        nitf_ListIterator end = nitf_List_end(record->graphics);

        while (nitf_ListIterator_notEqualTo(&iter, &end))
        {
            nitf_GraphicSegment *segment =
                (nitf_GraphicSegment *) nitf_ListIterator_get(&iter);

            showGraphicSubheader(segment->subheader);
            nitf_ListIterator_increment(&iter);
        }
    }

    num = nitf_Record_getNumLabels(record, &error);
    if (NITF_INVALID_NUM_SEGMENTS( num ) )
        goto CATCH_ERROR;

    if (num)
    {
        /*  Walk each label and show  */
        nitf_ListIterator iter = nitf_List_begin(record->labels);
        nitf_ListIterator end = nitf_List_end(record->labels);

        while (nitf_ListIterator_notEqualTo(&iter, &end))
        {
            nitf_LabelSegment *segment =
                (nitf_LabelSegment *) nitf_ListIterator_get(&iter);

            showLabelSubheader(segment->subheader);
            nitf_ListIterator_increment(&iter);
        }
    }

    num = nitf_Record_getNumTexts(record, &error);
    if (NITF_INVALID_NUM_SEGMENTS( num ) )
        goto CATCH_ERROR;

    if (num)
    {
        /*  Walk each text and show  */
        nitf_ListIterator iter = nitf_List_begin(record->texts);
        nitf_ListIterator end = nitf_List_end(record->texts);

        while (nitf_ListIterator_notEqualTo(&iter, &end))
        {
            nitf_TextSegment *segment =
                (nitf_TextSegment *) nitf_ListIterator_get(&iter);

            showTextSubheader(segment->subheader);
            nitf_ListIterator_increment(&iter);
        }
    }


    num = nitf_Record_getNumDataExtensions(record, &error);
    if (NITF_INVALID_NUM_SEGMENTS( num ) )
        goto CATCH_ERROR;

    if (num)
    {
        /*  Walk each dataExtension and show  */
        nitf_ListIterator iter = nitf_List_begin(record->dataExtensions);
        nitf_ListIterator end = nitf_List_end(record->dataExtensions);

        while (nitf_ListIterator_notEqualTo(&iter, &end))
        {
            nitf_DESegment *segment =
                (nitf_DESegment *) nitf_ListIterator_get(&iter);

            showDESubheader(segment->subheader);
            nitf_ListIterator_increment(&iter);
        }
    }

    num = nitf_Record_getNumReservedExtensions(record, &error);
    if (NITF_INVALID_NUM_SEGMENTS( num ) )
        goto CATCH_ERROR;

    if (num)
    {
        /*  Walk each reservedextension and show  */
        nitf_ListIterator iter =
            nitf_List_begin(record->reservedExtensions);
        nitf_ListIterator end = nitf_List_end(record->reservedExtensions);

        while (nitf_ListIterator_notEqualTo(&iter, &end))
        {
            nitf_RESegment *segment =
                (nitf_RESegment *) nitf_ListIterator_get(&iter);

            showRESubheader(segment->subheader);
            nitf_ListIterator_increment(&iter);
        }
    }

    //
    // Writer test code added to illustrate bugs 2 and 6
    //

    nitf_Writer * writer;
    nitf_IOHandle output;

    /* Open the output IO Handle */
    output = nitf_IOHandle_create("/dev/null", NITF_ACCESS_WRITEONLY, NITF_CREATE, &error);
    if (NITF_INVALID_HANDLE(output)) goto CATCH_ERROR;

    writer = nitf_Writer_construct(&error);
    if (!writer) goto CATCH_ERROR;

    /* prepare the writer with this record */
    if (!nitf_Writer_prepare(writer, record, output, &error))
    goto CATCH_ERROR;

    /*measureComplexity(record);*/

    nitf_IOHandle_close(io);
    nitf_Record_destruct(&record);
    nitf_Reader_destruct(&reader);

    return 0;

CATCH_ERROR:
    printf("We had a problem reading the file\n");
    nitf_Error_print(&error, stdout, "Exiting...");
    exit(EXIT_FAILURE);
}


