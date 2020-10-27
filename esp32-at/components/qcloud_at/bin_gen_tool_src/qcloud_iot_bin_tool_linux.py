#!/bin/env python
# -*- coding: utf-8 -*-

'''
Author: Spike Lin(spikelin@tencent.com)
Date： 2019-05-28 (v1.0)  "init version"
        2019-07-08 (v1.1) "update crypt"
        2019-08-12 (v1.2) "add CRC32"
'''

Tool_Version = 'v1.2'

from csv import DictReader
from argparse import ArgumentParser
from ctypes import cdll
from zlib import crc32
import os

# QCloud IoT AT ESP bin file generation tools 

BIN_FILE_SIZE = 1024

MODINFO_MODULE_NAME_SIZE = 32
DEVINFO_TLS_MODE_SIZE = 4

DEVINFO_PRODUCT_ID_SIZE = 10
DEVINFO_PRODUCT_ID_PAD_SIZE = 12
DEVINFO_DEV_NAME_SIZE = 48
DEVINFO_DEV_NAME_PAD_SIZE = 52
DEVINFO_DEV_SECRET_SIZE = 44
DEVINFO_DEV_SEC_CRY_PAD_SIZE = 72

OS_FILE_PATH = '/'
cutils = cdll.LoadLibrary(os.getcwd()+OS_FILE_PATH+"libutils.so")

def zero_padding(text, padding_len):
    text_length = len(text.encode('utf8'))
    if text_length % padding_len != 0:
        add = padding_len - (text_length % padding_len)
    else:
        add = 0
    pad_text = text + ('\0' * add)
    return pad_text


def byte_padding(data, padding_len, pad_byte):
    text_length = len(data)
    if text_length % padding_len != 0:
        add = padding_len - (text_length % padding_len)
    else:
        add = 0
    pad_data = data + (bytes([pad_byte]) * add)
    return pad_data


def byte_shift(data_bytes):
    data=bytearray(data_bytes)
    i = 0
    while i<(len(data)-1):
        temp = data[i]
        data[i] = data[i+1]
        data[i+1] = temp
        i+=2

    return bytes(data)


def convert_devinfo_to_file(pid, dev_name, psk_key, output_file_name, tls=1):
    if not pid or not dev_name or not psk_key:
        print("Null device info")
        return

    if len(pid.encode('utf8')) != DEVINFO_PRODUCT_ID_SIZE:
        print("Invalid Product ID: " + pid)
        return

    if len(dev_name.encode('utf8')) == 0 or len(dev_name.encode('utf8')) > DEVINFO_DEV_NAME_SIZE:
        print("Invalid Device Name: " + dev_name)
        return

    if len(psk_key.encode('utf8')) == 0 or len(psk_key.encode('utf8')) > DEVINFO_DEV_SECRET_SIZE:
        print("Invalid Device Secret: " + psk_key)
        return

    pid_pad = byte_padding(bytes(pid, "utf8"), DEVINFO_PRODUCT_ID_PAD_SIZE, 0)
    dev_name_pad = byte_padding(bytes(dev_name, "utf8"), DEVINFO_DEV_NAME_PAD_SIZE, 0)
    dev_key_pad = byte_padding(bytes(psk_key, "utf8"), DEVINFO_DEV_SEC_CRY_PAD_SIZE, 0)

    ret = cutils.update_devinfo(86013388, pid_pad, dev_name_pad, dev_key_pad)
    if ret != 0:
        print("encrypt failed:", ret)
        return

    header = bytes([0x0D, 0xF0, 0xDE, 0xC0, tls, 0, 0, 0])
    dev_info = header+pid_pad+dev_name_pad+dev_key_pad
    crc_bytes = crc32(dev_info).to_bytes(4, byteorder="little", signed=False)
    dev_info_pad = byte_padding(dev_info+crc_bytes, BIN_FILE_SIZE, 255)
    with open(output_file_name, "wb") as file_out:
        file_out.write(dev_info_pad)


def gen_devinfo_bin_files(input_filename, output_file_path):
    with open(input_filename, 'rt', encoding='utf8') as input_file:
        reader = DictReader(input_file, delimiter=',')
        for row in reader:
            print("Converting device info: "+row["ProductID"]+" "+row["DeviceName"])
            output_file_name = output_file_path+'DevInfo_'+row["ProductID"]+'_'+row["DeviceName"]+'.bin'
            convert_devinfo_to_file(row["ProductID"], row["DeviceName"], row["DeviceSecret"], output_file_name)
            print("Generated bin file: " + output_file_name)


def gen_prdinfo_bin_files(input_filename, output_file_path):
    with open(input_filename, 'rt', encoding='utf8') as input_file:
        reader = DictReader(input_file, delimiter=',')
        for row in reader:
            print("Converting product info: "+row["ProductID"]+" "+row["DeviceName"])
            output_file_name = output_file_path+'PrdInfo_'+row["ProductID"]+'_'+row["DeviceName"]+'.bin'
            convert_devinfo_to_file(row["ProductID"], row["DeviceName"], row["ProductSecret"], output_file_name)
            print("Generated bin file: " + output_file_name)


def convert_modinfo_to_file(module_name, flash_size_s, wifi_gpio_s,
                                fw_info_addr_s, fw_base_addr_s, fw_max_size_s, fixed_conn_id_s, output_file_name):

    if len(module_name.encode('utf8')) == 0 or len(module_name.encode('utf8')) > 30:
        print("Invalid Module Name:", module_name)
        return

    flash_size = int(flash_size_s)
    if flash_size != 2 and flash_size != 4:
        print("Invalid flash size:", flash_size)
        return

    wifi_gpio = int(wifi_gpio_s)
    if wifi_gpio < 0 or wifi_gpio > 16:
        print("Invalid wifi state GPIO:", wifi_gpio)
        return

    fw_info_addr = int(fw_info_addr_s, 0)
    if fw_info_addr < 0x111000 or fw_info_addr % 4096:
        print("Invalid fw info addr:", fw_info_addr)
        return

    fw_base_addr = int(fw_base_addr_s, 0)
    if fw_base_addr < 0x111000 or fw_base_addr % 4096:
        print("Invalid fw base addr:", fw_base_addr)
        return

    fw_max_size = int(fw_max_size_s, 0)
    if fw_max_size > 700*1024:
        print("Invalid fw max size:", fw_max_size)
        return

    fixed_conn_id = int(fixed_conn_id_s, 0)
    
    #header = bytes([0x0D, 0xF0, 0xDE, 0xC0])
    header = (0xC0DEF00D).to_bytes(4, byteorder="little", signed=False)
    mod_name_pad = zero_padding(module_name, MODINFO_MODULE_NAME_SIZE)
    flash_size_b = flash_size.to_bytes(4, byteorder="little", signed=False)
    wifi_gpio_b = wifi_gpio.to_bytes(4, byteorder="little", signed=False)
    fw_info_addr_b = fw_info_addr.to_bytes(4, byteorder="little", signed=False)
    fw_base_addr_b = fw_base_addr.to_bytes(4, byteorder="little", signed=False)
    fw_max_size_b = fw_max_size.to_bytes(4, byteorder="little", signed=False)
    fixed_conn_id_b = fixed_conn_id.to_bytes(4, byteorder="little", signed=False)
    mod_info = header+bytes(mod_name_pad, 'utf8')+flash_size_b+wifi_gpio_b+fw_info_addr_b+fw_base_addr_b+fw_max_size_b+fixed_conn_id_b
    crc_bytes = crc32(mod_info).to_bytes(4, byteorder="little", signed=False)
    mod_info_pad = byte_padding(mod_info+crc_bytes, BIN_FILE_SIZE, 255)
    with open(output_file_name, "wb") as file_out:
        file_out.write(mod_info_pad)


def gen_modinfo_bin_files(input_filename, output_file_path):
    with open(input_filename, 'rt', encoding='utf8') as input_file:
        reader = DictReader(input_file, delimiter=',')
        for row in reader:
            print("Converting module info:", row["ModuleName"])
            output_file_name = output_file_path+'ModInfo_'+row["ModuleName"]+'_'+row["FlashSize"]+'MB_GPIO'+row["WiFiGPIO"]+'.bin'
            convert_modinfo_to_file(row["ModuleName"], row["FlashSize"], row["WiFiGPIO"],
                                        row["FwInfoAddr"], row["FwBaseAddr"], row["FwMaxSize"], row["FixedConnId"], output_file_name)
            print("Generated bin file:", output_file_name)


def mkdir(path):
    folder = os.path.exists(path)

    if not folder:
        print("create folder " + path)
        os.makedirs(path)


def main():
    parser = ArgumentParser(description="QCloud IoT ESP bin files generation tool",
                                     epilog="e.g.  %(prog)s -t DEV -i devinfo_list_sample.csv")
    parser.add_argument('--version', '-v', action='version', version='%(prog)s: '+Tool_Version)
    bin_gen_group = parser.add_argument_group('To generate bin files')
    bin_gen_group.add_argument(
            "--input", "-i", required=True,
            help="Path to device/product/module info CSV file.",
            default='devinfo_list_sample.csv')

    bin_gen_group.add_argument(
            "--output", "-o",
            help='Folder path to output converted bin files.',
            default='output')
    
    bin_gen_group.add_argument(
            "--type", "-t", required=True,
            help="Input file type: DEV/PRD/MOD",
            default='DEV')

    args = parser.parse_args()
    input_filename = args.input
    if not os.access(input_filename, os.R_OK):
        print("ERROR: "+input_filename+" is not readable!")
        return

    output_filepath = args.output
    if output_filepath == 'output':
        output_filepath = os.getcwd()+OS_FILE_PATH+output_filepath+OS_FILE_PATH
    else:
        output_filepath = output_filepath+OS_FILE_PATH
        
    mkdir(output_filepath)

    input_type = args.type
    if input_type.upper() == 'DEV':
        gen_devinfo_bin_files(input_filename, output_filepath)
    elif input_type.upper() == 'PRD':
        gen_prdinfo_bin_files(input_filename, output_filepath)
    elif input_type.upper() == 'MOD':
        gen_modinfo_bin_files(input_filename, output_filepath)
    else:
        print("ERROR: invalid input type", input_type)


if __name__ == "__main__":
    main()