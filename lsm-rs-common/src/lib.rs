#![no_std]

use core::primitive::str;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum EventType {
    Exec,
    FileOpen
}

#[derive(Clone)]
#[repr(C)]
pub struct Event {
    pub etype: EventType,
    pub path: [u8; 128],
    pub uid: u32,
    pub gid: u32,
    pub dev: u32,
    pub inode: u64,
    pub argc: u32,
    pub argv: [u8; 128],
}