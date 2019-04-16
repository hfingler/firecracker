// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std;
use std::ffi::CStr;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, repeat};
use std::mem;
use std::fs::File;
use std::path::Path;

use memory_model::{GuestAddress, GuestMemory, DataInit};
use sys_util;

extern crate byteorder;
use self::byteorder::{ReadBytesExt, NativeEndian, LittleEndian, BigEndian};

#[allow(non_camel_case_types)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Add here any other architecture that uses as kernel image an ELF file.
pub mod elf;

#[allow(dead_code)]
mod multiboot;

unsafe impl DataInit for multiboot::multiboot_mmap_entry {}

#[derive(Debug, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    CommandLineCopy,
    CommandLineOverflow,
    InvalidElfMagicNumber,
    InvalidEntryAddress,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    InvalidProgramHeaderAddress,
    ReadElfHeader,
    ReadKernelImage,
    ReadProgramHeader,
    SeekKernelStart,
    SeekKernelImage,
    SeekProgramHeader,
    NotMultibootKernel,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::BigEndianElfOnLittle => "Unsupported ELF File byte order",
                Error::CommandLineCopy => "Failed to copy the command line string to guest memory",
                Error::CommandLineOverflow => "Command line string overflows guest memory",
                Error::InvalidElfMagicNumber => "Invalid ELF magic number",
                Error::InvalidEntryAddress => "Invalid entry address found in ELF header",
                Error::InvalidProgramHeaderSize => "Invalid ELF program header size",
                Error::InvalidProgramHeaderOffset => "Invalid ELF program header offset",
                Error::InvalidProgramHeaderAddress => "Invalid ELF program header address",
                Error::ReadElfHeader => "Failed to read ELF header",
                Error::ReadKernelImage => "Failed to write kernel image to guest memory",
                Error::ReadProgramHeader => "Failed to read ELF program header",
                Error::SeekKernelStart => {
                    "Failed to seek to file offset as pointed by the ELF program header"
                }
                Error::SeekKernelImage => "Failed to seek to offset of kernel image",
                Error::SeekProgramHeader => "Failed to seek to ELF program header",
                Error::NotMultibootKernel => "Not a multiboot kernel",
            }
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// global address so we dont have to seek and find magic twice
static mut mb_magic_offset: u32 = 0;

/// Checks if a kernel is a multiboot compliant kernel
///
/// # Arguments
///
/// * `kernel_image` - Input kernel.
///
/// Returns bool.
/// 
pub fn is_multiboot<F>(
    kernel_image: &mut F
) -> Result<bool>
where
    F: Read + Seek,
{
    let kernel_file_size = kernel_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekKernelImage)?;

    println!("size: {}", kernel_file_size);

    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;

    //mb magic has to be in the first 8192-size of header (=12*u32)
    //but we need to read flags and checksum, so we need 8192/4-12+3
    
    const BUF_LEN: usize = (multiboot::MULTIBOOT_SEARCH as usize / 4) - 9;
    let mut buf: [u32; BUF_LEN] = [0; BUF_LEN];
    
    //let buf_sz = std::cmp::max(kernel_file_size as usize, BUF_LEN);
    //let mut buf = Vec::with_capacity(buf_sz);


    //read MB_HEADER_U32_SZ u32 from elf
    match kernel_image.read_u32_into::<NativeEndian>(&mut buf) {
        Err(err) => panic!("kernel_image read u32: {}", err),
        _ => println!("all good"),
    }
    
    println!("Read u32s, scanning for magic");
    //.unwrap();

    for (i, l) in buf.iter().enumerate() {
        if *l == multiboot::MULTIBOOT_BOOTLOADER_MAGIC {
            let mb_flags = buf[i+1];
            let mb_check = buf[i+2];
            println!("found at byte {}", i*4);
            println!("found at byte {}", i*4);
            println!("flags: {:#X}  check:  {:#X}", mb_flags, mb_check);

            if mb_flags as i32 + mb_check as i32 + multiboot::MULTIBOOT_BOOTLOADER_MAGIC as i32 == 0 {
                println!("it matches!");
                println!("found at byte {}", i*4);
                unsafe { mb_magic_offset = (i*4) as u32; }
                /*
                //get multiboot header
                let mut mhdr: multiboot::multiboot_header = Default::default();
                kernel_image
                    .seek(SeekFrom::Start((i*4) as u64))
                    .map_err(|_| Error::SeekKernelImage)?;
                unsafe {
                    // read_struct is safe when reading a POD struct.  It can be used and dropped without issue.
                    sys_util::read_struct(kernel_image, &mut mhdr).map_err(|_| Error::NotMultibootKernel)?;
                }
                println!("mboot header: {:?}", mhdr);
                */
                return Ok(true);
            }
        }
    }

    println!("not multiboot");
    return Ok(false);
}  

pub fn page_align_4k(addr: u32) -> u32
{
    return ((addr + 0x1000 - 1)) & (!(0x1000-1))
    //(((addr) + TARGET_PAGE_SIZE - 1) & TARGET_PAGE_MASK)
}

/// Loads a multiboot kernel from elf
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_image` - Input vmlinux image.
/// * `start_address` - For x86_64, this is the start of the high memory. Kernel should reside above it.
///
/// Returns the entry address of the kernel.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn load_multiboot_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_image: &mut F,
    start_address: usize,
    cmdline: &CStr,
) -> Result<(GuestAddress, GuestAddress)>
where
    F: Read + Seek,
{
    let mut mb_magic_offset_l : u32 = 0;
    unsafe { mb_magic_offset_l = mb_magic_offset; }

    //get multiboot header
    let mut mhdr: multiboot::multiboot_header = Default::default();
    kernel_image
        .seek(SeekFrom::Start(mb_magic_offset_l as u64))
        .map_err(|_| Error::SeekKernelImage)?;
    unsafe {
        // read_struct is safe when reading a POD struct.  It can be used and dropped without issue.
        sys_util::read_struct(kernel_image, &mut mhdr).map_err(|_| Error::NotMultibootKernel)?;
    }
    println!("mboot header: {:?}", mhdr);

    let kernel_file_size = kernel_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekKernelImage)?;

    //offset of kernel start in input file. for rumprun it's jsut the magic offset.
    let mb_kernel_text_offset : u32 = mb_magic_offset_l - (mhdr.header_addr - mhdr.load_addr);
    let mut mb_load_size : u32 = 0;
    let mb_kernel_size : u32;

    if mhdr.header_addr < mhdr.load_addr {
        panic!("invalid load_addr address");
    }
    if mhdr.header_addr - mhdr.load_addr > mb_magic_offset_l {
        panic!("invalid header_addr address");
    }

    //true for rumprun
    if mhdr.load_end_addr != 0 {
        if mhdr.load_end_addr < mhdr.load_addr {
            panic!("er1")
        }
        //load size is the amount of bytes of text+data sections
        mb_load_size = mhdr.load_end_addr - mhdr.load_addr;
    }
    else {
        if (kernel_file_size as u32) < mb_kernel_text_offset {
            panic!("invalid kernel_file_size")
        }
        mb_load_size = kernel_file_size as u32 - mb_kernel_text_offset;
    }

    if mb_load_size > std::u32::MAX - mhdr.load_addr {
        panic!("kernel does not fit in address space");
    }
    //true for rumprun
    if mhdr.bss_end_addr != 0 {
        if mhdr.bss_end_addr < (mhdr.load_addr + mb_load_size) {
            panic!("invalid bss_end_addr address");
        }
        //kernel size = text+data+bss
        mb_kernel_size = mhdr.bss_end_addr - mhdr.load_addr;
    } else {
        mb_kernel_size = mb_load_size;
    }

    //read into guests memory
    kernel_image
        .seek(SeekFrom::Start(mb_kernel_text_offset as u64))
        .map_err(|_| Error::SeekKernelImage)?;
    //firecracker: for i386, guest memory starts at 0.
    //load kernel at load_addr in mb header
    let mem_offset = GuestAddress(mhdr.load_addr as usize);
    guest_mem.read_to_memory(mem_offset, kernel_image, mb_load_size as usize);
    
    //we need to zero bss section
    let zero_start_addr = GuestAddress((mhdr.load_addr + mb_load_size) as usize);
    let zeroes_sz = (mb_kernel_size - mb_load_size) as usize; 
    guest_mem.read_to_memory(zero_start_addr, &mut std::io::repeat(0), zeroes_sz)
        .map_err(|_| Error::SeekKernelImage)?; 

    //write cmdline after multiboot area
    let cmd_addr = GuestAddress(
        (mhdr.load_addr + mb_kernel_size + mem::size_of::<multiboot::multiboot_info>() as u32 ) as usize
    );
    guest_mem
        .write_slice_at_addr(cmdline.to_bytes_with_nul(), cmd_addr)
        .map_err(|_| Error::CommandLineCopy)?;

    //now we need to create a multiboot_info struct, write it to memory
    //and make ebx point to it
    //TODO: make sure of alignments
    //let cmd_addr_u32 = page_align_4k(mb_kernel_size);
    let mbinfo_addr = GuestAddress((mhdr.load_addr + mb_kernel_size) as usize);

    let mut mbinfo: multiboot::multiboot_info = unsafe { mem::zeroed() };
    mbinfo.flags = 0 as u32;
    mbinfo.flags = mbinfo.flags | multiboot::MULTIBOOT_INFO_CMDLINE;
    mbinfo.cmdline = cmd_addr.offset() as u32;
    
    //set up memory
    mbinfo.flags = mbinfo.flags | multiboot::MULTIBOOT_INFO_MEMORY;
    mbinfo.flags = mbinfo.flags | multiboot::MULTIBOOT_INFO_MEM_MAP;

    let mut mmap_entry : multiboot::multiboot_mmap_entry = unsafe { mem::zeroed() };
    mmap_entry.size = 0;
    mmap_entry.addr = 0x10_0000;

    if guest_mem.num_regions() != 1 {
        panic!("cant handle 2 regions yet")
    }
    mmap_entry.len = guest_mem.end_addr().0 as u64;
    mmap_entry.type_ = multiboot::MULTIBOOT_MEMORY_AVAILABLE;

    let mmap_addr = cmd_addr
        .checked_add(cmdline.to_bytes().len())
        .ok_or(Error::CommandLineOverflow)?;
    guest_mem.write_obj_at_addr(mmap_entry, mmap_addr);

    mbinfo.mmap_addr = mmap_addr.0 as u32;
    mbinfo.mmap_length = mem::size_of::<multiboot::multiboot_mmap_entry>() as u32;
    
    //lets hope this is enough... please
    Ok((GuestAddress(mhdr.entry_addr as usize), mbinfo_addr) )
}



/// Loads a kernel from a vmlinux elf image to a slice
///
/// # Arguments
///
/// * `guest_mem` - The guest memory region the kernel is written to.
/// * `kernel_image` - Input vmlinux image.
/// * `start_address` - For x86_64, this is the start of the high memory. Kernel should reside above it.
///
/// Returns the entry address of the kernel.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn load_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_image: &mut F,
    start_address: usize
) -> Result<(GuestAddress)>
where
    F: Read + Seek,
{
    let mut ehdr: elf::Elf64_Ehdr = Default::default();
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;
    unsafe {
        // read_struct is safe when reading a POD struct.  It can be used and dropped without issue.
        sys_util::read_struct(kernel_image, &mut ehdr).map_err(|_| Error::ReadElfHeader)?;
    }

    // Sanity checks
    if ehdr.e_ident[elf::EI_MAG0 as usize] != elf::ELFMAG0 as u8
        || ehdr.e_ident[elf::EI_MAG1 as usize] != elf::ELFMAG1
        || ehdr.e_ident[elf::EI_MAG2 as usize] != elf::ELFMAG2
        || ehdr.e_ident[elf::EI_MAG3 as usize] != elf::ELFMAG3
    {
        return Err(Error::InvalidElfMagicNumber);
    }
    if ehdr.e_ident[elf::EI_DATA as usize] != elf::ELFDATA2LSB as u8 {
        return Err(Error::BigEndianElfOnLittle);
    }
    if ehdr.e_phentsize as usize != mem::size_of::<elf::Elf64_Phdr>() {
        return Err(Error::InvalidProgramHeaderSize);
    }
    if (ehdr.e_phoff as usize) < mem::size_of::<elf::Elf64_Ehdr>() {
        // If the program header is backwards, bail.
        return Err(Error::InvalidProgramHeaderOffset);
    }
    if (ehdr.e_entry as usize) < start_address {
        return Err(Error::InvalidEntryAddress);
    }

    kernel_image
        .seek(SeekFrom::Start(ehdr.e_phoff))
        .map_err(|_| Error::SeekProgramHeader)?;
    let phdrs: Vec<elf::Elf64_Phdr> = unsafe {
        // Reading the structs is safe for a slice of POD structs.
        sys_util::read_struct_slice(kernel_image, ehdr.e_phnum as usize)
            .map_err(|_| Error::ReadProgramHeader)?
    };

    // Read in each section pointed to by the program headers.
    for phdr in &phdrs {
        if (phdr.p_type & elf::PT_LOAD) == 0 || phdr.p_filesz == 0 {
            continue;
        }

        kernel_image
            .seek(SeekFrom::Start(phdr.p_offset))
            .map_err(|_| Error::SeekKernelStart)?;

        let mem_offset = GuestAddress(phdr.p_paddr as usize);
        if mem_offset.offset() < start_address {
            return Err(Error::InvalidProgramHeaderAddress);
        }

        guest_mem
            .read_to_memory(mem_offset, kernel_image, phdr.p_filesz as usize)
            .map_err(|_| Error::ReadKernelImage)?;
    }
    
    Ok(GuestAddress(ehdr.e_entry as usize))
}

#[cfg(target_arch = "aarch64")]
pub fn load_kernel<F>(
    guest_mem: &GuestMemory,
    kernel_image: &mut F,
    start_address: usize,
    cmdline: &CStr,
) -> Result<(GuestAddress, Option<uestAddress>)>
where
    F: Read + Seek,
{
    /* Kernel boot protocol is specified in the kernel docs
    Documentation/arm/Booting and Documentation/arm64/booting.txt.

    ======aarch64 kernel header========
    u32 code0;			/* Executable code */
    u32 code1;			/* Executable code */
    u64 text_offset;		/* Image load offset, little endian */
    u64 image_size;		/* Effective Image size, little endian */
    u64 flags;			/* kernel flags, little endian */
    u64 res2	= 0;		/* reserved */
    u64 res3	= 0;		/* reserved */
    u64 res4	= 0;		/* reserved */
    u32 magic	= 0x644d5241;	/* Magic number, little endian, "ARM\x64" */
    u32 res5;			/* reserved (used for PE COFF offset) */
    ====================================
     */
    const AARCH64_KERNEL_LOAD_ADDR: usize = 0x80000;
    const AARCH64_MAGIC_NUMBER: u32 = 0x644d5241;
    const AARCH64_MAGIC_OFFSET_HEADER: u64 =
        2 * mem::size_of::<u32>() as u64 + 6 * mem::size_of::<u64>() as u64; // This should total 56.
    const AARCH64_TEXT_OFFSET: u64 = 2 * mem::size_of::<u32>() as u64;
    let mut kernel_load_offset = AARCH64_KERNEL_LOAD_ADDR;

    /* Look for the magic number inside the elf header. */
    kernel_image
        .seek(SeekFrom::Start(AARCH64_MAGIC_OFFSET_HEADER))
        .map_err(|_| Error::SeekKernelImage)?;
    let mut magic_number: u32 = 0;
    unsafe {
        sys_util::read_struct(kernel_image, &mut magic_number)
            .map_err(|_| Error::ReadProgramHeader)?
    }
    if u32::from_le(magic_number) != AARCH64_MAGIC_NUMBER {
        return Err(Error::InvalidElfMagicNumber);
    }

    /* Look for the `text_offset` from the elf header. */
    kernel_image
        .seek(SeekFrom::Start(AARCH64_TEXT_OFFSET)) // This should total 8.
        .map_err(|_| Error::SeekKernelImage)?;
    let mut hdrvals: [u64; 2] = [0; 2];
    unsafe {
        /* `read_struct` is safe when reading a POD struct. It can be used and dropped without issue. */
        sys_util::read_struct(kernel_image, &mut hdrvals).map_err(|_| Error::ReadProgramHeader)?;
    }
    /* Following the boot protocol mentioned above. */
    if u64::from_le(hdrvals[1]) != 0 {
        kernel_load_offset = u64::from_le(hdrvals[0]) as usize;
    }
    /* Get the total size of kernel image. */
    let kernel_size = kernel_image
        .seek(SeekFrom::End(0))
        .map_err(|_| Error::SeekKernelImage)?;

    /* Last `seek` will leave the image with the cursor at its end, rewind it to start. */
    kernel_image
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::SeekKernelImage)?;

    kernel_load_offset = kernel_load_offset + start_address;
    guest_mem
        .read_to_memory(
            GuestAddress(kernel_load_offset),
            kernel_image,
            kernel_size as usize,
        )
        .map_err(|_| Error::ReadKernelImage)?;

    Ok((GuestAddress(kernel_load_offset), None))
}

/// Writes the command line string to the given memory slice.
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
/// * `guest_addr` - The address in `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line.
pub fn load_cmdline(
    guest_mem: &GuestMemory,
    guest_addr: GuestAddress,
    cmdline: &CStr,
) -> Result<()> {
    let len = cmdline.to_bytes().len();
    if len == 0 {
        return Ok(());
    }

    let end = guest_addr
        .checked_add(len + 1)
        .ok_or(Error::CommandLineOverflow)?; // Extra for null termination.
    if end > guest_mem.end_addr() {
        return Err(Error::CommandLineOverflow)?;
    }

    guest_mem
        .write_slice_at_addr(cmdline.to_bytes_with_nul(), guest_addr)
        .map_err(|_| Error::CommandLineCopy)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory_model::{GuestAddress, GuestMemory};
    use std::io::Cursor;

    const MEM_SIZE: usize = 0x18_0000;

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap()
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn make_test_bin() -> Vec<u8> {
        include_bytes!("test_elf.bin").to_vec()
    }

    #[cfg(target_arch = "aarch64")]
    fn make_test_bin() -> Vec<u8> {
        include_bytes!("test_pe.bin").to_vec()
    }

    #[test]
    // Tests that loading the kernel is successful on different archs.
    fn test_load_kernel() {
        let gm = create_guest_mem();
        let image = make_test_bin();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let load_addr = 0x10_0000;
        #[cfg(target_arch = "aarch64")]
        let load_addr = 0x8_0000;
        assert_eq!(
            Ok(GuestAddress(load_addr)),
            load_kernel(&gm, &mut Cursor::new(&image), 0)
        );
    }

    #[test]
    fn test_load_kernel_no_memory() {
        let gm = GuestMemory::new(&[(GuestAddress(0x0), 79)]).unwrap();
        let image = make_test_bin();
        assert_eq!(
            Err(Error::ReadKernelImage),
            load_kernel(&gm, &mut Cursor::new(&image), 0)
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_load_bad_kernel() {
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        bad_image.truncate(56);
        assert_eq!(
            Err(Error::ReadProgramHeader),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[test]
    fn test_bad_kernel_magic() {
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let offset = 0x1;
        #[cfg(target_arch = "aarch64")]
        let offset = 0x38;
        bad_image[offset] = 0x33;
        assert_eq!(
            Err(Error::InvalidElfMagicNumber),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_endian() {
        // Only little endian is supported.
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        bad_image[0x5] = 2;
        assert_eq!(
            Err(Error::BigEndianElfOnLittle),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_bad_kernel_phoff() {
        // program header has to be past the end of the elf header
        let gm = create_guest_mem();
        let mut bad_image = make_test_bin();
        bad_image[0x20] = 0x10;
        assert_eq!(
            Err(Error::InvalidProgramHeaderOffset),
            load_kernel(&gm, &mut Cursor::new(&bad_image), 0)
        );
    }

    #[test]
    fn test_cmdline_overflow() {
        let gm = create_guest_mem();
        let cmdline_address = GuestAddress(MEM_SIZE - 5);
        assert_eq!(
            Err(Error::CommandLineOverflow),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"12345\0").unwrap(),
            )
        );
    }

    #[test]
    fn test_cmdline_write_end() {
        let gm = create_guest_mem();
        let mut cmdline_address = GuestAddress(45);
        assert_eq!(
            Ok(()),
            load_cmdline(
                &gm,
                cmdline_address,
                CStr::from_bytes_with_nul(b"1234\0").unwrap(),
            )
        );
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'4');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj_from_addr(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }
}
