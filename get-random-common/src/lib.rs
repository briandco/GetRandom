#![no_std]

#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub pid: u32,
    pub uid: u32,  
}

