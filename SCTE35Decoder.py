#!/usr/bin/python
'''

SCTE-35 Decoder


The MIT License (MIT)

Copyright (c) 2014 Al McCormack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

'''


import bitstring
from datetime import timedelta


class MixinDictRepr(object):
    def __repr__(self, *args, **kwargs):
        return repr(self.__dict__)

class SCTE35_ParseException(Exception):
    pass

class SCTE35_SpliceInfoSectionException(Exception):
    pass

class SCTE35_SpliceInfoSection(MixinDictRepr):
    
    def __init__(self, table_id):
        if table_id != 0xfc:
            raise SCTE35_SpliceInfoSectionException("%d valid. Should be 0xfc" %
                                                    table_id)

class MPEG_Time(long):
    """ Relative time represented by 90kHz clock """
    
    @property
    def seconds(self):
        return self / 90000.0
    
    @property
    def timedelta(self):
        return timedelta(seconds=self.seconds)
    
    def __repr__(self, *args, **kwargs):
        return "%d (seconds: %f, time: %s)" % (self, self.seconds, self.timedelta)

class SCTE35_SpliceInsert(MixinDictRepr):
    
    class Splice_Time(MixinDictRepr):
        def __init__(self):
            self.time_specified_flag =  None
            self.pts_time = None

    class Component(MixinDictRepr):
        def __init__(self, tag):
            self.tag = tag
            self.splice_time = None
            
    class BreakDuration(MixinDictRepr):
        def __init__(self):
            self.auto_return = None
            self.duration = None
    
    def __init__(self, splice_id):
        self.splice_id = splice_id
        self.components = []

class SCTE35_TimeSignal(MixinDictRepr):
    
    class Splice_Time(MixinDictRepr):
        def __init__(self):
            self.time_specified_flag =  None
            self.pts_time = None

    def __init__(self):
        self.splice_time = None
        
    
class SCTE35_SpliceDescriptor(MixinDictRepr):
    def __init__(self):
        self.descriptor_length = None
        self.splice_descriptor_tag = None
        self.identifier = None 

class SCTE35_SegmentationDescriptor(SCTE35_SpliceDescriptor):
    def __init__(self):
        super(SCTE35_SegmentationDescriptor, self).__init__()
        self.segmentation_event_id = None
        self.segmentation_event_cancel_indicator = None
        self.program_segmentation_flag = None
        self.segmentation_duration_flag = None
        self.delivery_not_restricted_flag = None
        self.web_delivery_allowed_flag = None
        self.no_regional_blackout_flag = None
        self.archive_allowed_flag = None
        self.device_restrictions = None
        self.component_count = None
        self.components = None
        self.segmentation_duration = None
        self.segmentation_upid_type = None
        self.segmentation_upid_length = None
        self.segmentation_upid = None
        self.segmentation_type_id = None
        self.segment_num = None
        self.segments_expected = None
        self.sub_segment_num = None
        self.sub_segments_expected = None

class SCTE35_Parser(object):
    
    def parse(self, input_bytes):
        input_bitarray = bitstring.BitString(bytes=input_bytes)

        table_id = input_bitarray.read("uint:8")
        splice_info_section = SCTE35_SpliceInfoSection(table_id)
        
        splice_info_section.section_syntax_indicator = input_bitarray.read("bool")
        splice_info_section.private = input_bitarray.read("bool")
        #private
        input_bitarray.pos += 2
        splice_info_section.section_length = input_bitarray.read("uint:12")
        splice_info_section.protocol_version = input_bitarray.read("uint:8")
        splice_info_section.encrypted_packet = input_bitarray.read("bool")
        splice_info_section.encryption_algorithm = input_bitarray.read("uint:6")
        splice_info_section.pts_adjustment = input_bitarray.read("uint:33")
        splice_info_section.cw_index = input_bitarray.read("uint:8")
        splice_info_section.tier = input_bitarray.read("hex:12")
        splice_info_section.splice_command_length = input_bitarray.read("uint:12")

        splice_info_section.splice_command_type = input_bitarray.read("uint:8")
        
        # splice command type parsing
        if splice_info_section.splice_command_type == 5:
            splice_info_section.splice_command = self.__parse_splice_insert(input_bitarray)
        elif splice_info_section.splice_command_type == 6:
            splice_info_section.splice_command = self.__parse_time_signal(input_bitarray)
        else:
            raise SCTE35_SpliceInfoSectionException("splice_command_type: %d not yet supported" % splice_info_section.splice_command_type)

        splice_info_section.splice_descriptor_loop_length = input_bitarray.read("uint:16")
        splice_info_section.splice_descriptors = None
        
        if splice_info_section.splice_descriptor_loop_length > 0:
            splice_info_section.splice_descriptors = \
             self.__parse_splice_descriptors(input_bitarray, 
                                             splice_info_section.splice_descriptor_loop_length)
        
        return splice_info_section
        
    def __parse_splice_time(self, bitarray):
        splice_time = SCTE35_SpliceInsert.Splice_Time()
        splice_time.time_specified_flag = bitarray.read("bool")
        
        if splice_time.time_specified_flag:
            # Reserved for 6 bits
            bitarray.pos += 6
            splice_time.pts_time = MPEG_Time(bitarray.read("uint:33"))
        else:
            bitarray.pos += 7
            
        return splice_time
            
    def __parse_break_duration(self, bitarray):
        break_duration = SCTE35_SpliceInsert.BreakDuration()
        break_duration.auto_return = bitarray.read("bool")
        bitarray.pos += 6
        break_duration.duration = MPEG_Time(bitarray.read("uint:33"))
        return break_duration

    def __parse_time_signal(self, bitarray):
        sts = SCTE35_TimeSignal()
        sts.splice_time = self.__parse_splice_time(bitarray)
        return sts
    
    def __parse_splice_insert(self, bitarray):
        splice_event_id = bitarray.read("uint:32")
        ssi = SCTE35_SpliceInsert(splice_event_id)
        
        ssi.splice_event_cancel_indicator = bitarray.read("bool")
        bitarray.pos += 7
        
        if not ssi.splice_event_cancel_indicator:
            ssi.out_of_network_indicator = bitarray.read("bool")
            ssi.program_splice_flag = bitarray.read("bool")
            ssi.duration_flag = bitarray.read("bool")
            ssi.splice_immediate_flag = bitarray.read("bool")
            # Next 4 bits are reserved
            bitarray.pos += 4
            
            if ssi.program_splice_flag and not ssi.splice_immediate_flag:
                ssi.splice_time = self.__parse_splice_time(bitarray)
                
            if not ssi.program_splice_flag:
                ssi.component_count = bitarray.read("uint:8")
                
                for i in xrange(0, ssi.component_count):
                    component = SCTE35_SpliceInsert.Component(bitarray.read("uint:8"))
                    if ssi.splice_immediate_flag:
                        component.splice_time = self.__parse_splice_time(bitarray)
                    ssi.components.append(component)
        
        
            if ssi.duration_flag:
                ssi.break_duration = self.__parse_break_duration(bitarray)
                
            ssi.unique_program_id = bitarray.read("uint:16")
            ssi.avail_num = bitarray.read("uint:8")
            ssi.avails_expected = bitarray.read("uint:8")
            return ssi
        
    def __parse_splice_descriptors(self, bitarray, length):
        
        results = []
        
        while length > 0:        
            splice_descriptor_tag = bitarray.read("uint:8")
            descriptor_length = bitarray.read("uint:8")
            identifier = bitarray.read("hex:32")

            length -= 6

            # parse avail_descriptor
            if splice_descriptor_tag == 0x00:
                raise SCTE35_SpliceInfoSectionException("avail_descriptor (%d) not yet supported" % splice_descriptor_tag)
            # parse DTMF_descriptor
            elif splice_descriptor_tag == 0x01:
                raise SCTE35_SpliceInfoSectionException("DTMF_descriptor (%d) not yet supported" % splice_descriptor_tag)
            # parse segmentation_descriptor
            elif splice_descriptor_tag == 0x02:
                splice_desc = SCTE35_SegmentationDescriptor()
                splice_desc.segmentation_event_id = bitarray.read("uint:32")
                splice_desc.segmentation_event_cancel_indicator = bitarray.read("bool")
                bitarray.pos += 7
                length -= 5
                if not splice_desc.segmentation_event_cancel_indicator:
                    splice_desc.program_segmentation_flag = bitarray.read("bool")
                    splice_desc.segmentation_duration_flag = bitarray.read("bool")
                    splice_desc.delivery_not_restricted_flag = bitarray.read("bool")

                    if not splice_desc.delivery_not_restricted_flag:
                        splice_desc.web_delivery_allowed_flag = bitarray.read("bool")
                        splice_desc.no_regional_blackout_flag = bitarray.read("bool")
                        splice_desc.archive_allowed_flag = bitarray.read("bool")
                        splice_desc.device_restrictions = bitarray.read("bin:2")
                    else:
                        bitarray.pos += 5
                    length -= 1

                    if not splice_desc.program_segmentation_flag:
                        splice_desc.component_count = bitarray.read("uint:8")
                        length -= 1
                        splice_desc.components = []
                        for i in range(splice_desc.component_count):
                            component = {}
                            component.component_tag = bitarray.read("uint:8")
                            bitarray.pos += 7
                            component.pts_offset = bitarray.read("uint:33")
                            splice_desc.components.append(component)
                            length -= 6

                    if splice_desc.segmentation_duration_flag:
                        splice_desc.segmentation_duration = bitarray.read("uint:40")
                        length -= 5

                    splice_desc.segmentation_upid_type = bitarray.read("hex:8")
                    splice_desc.segmentation_upid_length = bitarray.read("uint:8")
                    splice_desc.segmentation_upid = bitarray.read("hex:" + str(splice_desc.segmentation_upid_length*8))
                    length -= (splice_desc.segmentation_upid_length + 2)

                    splice_desc.segmentation_type_id = bitarray.read("uint:8")
                    splice_desc.segment_num = bitarray.read("uint:8")
                    splice_desc.segments_expected = bitarray.read("uint:8")
                    length -= 3

                    if splice_desc.segmentation_type_id == 0x34 or splice_desc.segmentation_type_id == 0x36:
                        splice_desc.sub_segment_num = bitarray.read("uint:8")
                        splice_desc.sub_segments_expected = bitarray.read("uint:8")
                        length -= 2
                
            # parse time_descriptor
            elif splice_descriptor_tag == 0x03:
                raise SCTE35_SpliceInfoSectionException("time_descriptor (%d) not yet supported" % splice_descriptor_tag)
            else:
                raise SCTE35_SpliceInfoSectionException("unknown splice_descriptor tag (%d)" % splice_descriptor_tag)

            splice_desc.splice_descriptor_tag = splice_descriptor_tag
            splice_desc.descriptor_length = descriptor_length
            splice_desc.identifier = identifier
    
            results.append( splice_desc )
        return results

if __name__ == "__main__":
    import base64
    import argparse
    import pprint
    
    description = """ Parse SCTE-35 markers from Base64 Strings.
Example String: "/DAlAAAAAAAAAP/wFAUAAAABf+/+LRQrAP4BI9MIAAEBAQAAfxV6SQ==" """
    
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('base64_scte35', metavar='SCTE35_Marker',
                   help='Base64 encoded SCTE-35 marker')
    
    args = parser.parse_args()
    
    myinput = base64.standard_b64decode(args.base64_scte35)
    
    splice_info_section = SCTE35_Parser().parse(myinput)

    print "Parsing Complete"
    
    pprint.pprint(vars(splice_info_section))
