#[derive(Debug, Clone, Copy)]
pub enum DataType {
    INT8,
    UINT8,
    INT16,
    UINT16,
    INT32,
    UINT32,
    INT64,
    UINT64,
    POINTER,
    STRING,
}


pub unsafe fn read_data<T>(ptr: *const u8, offset: usize) -> T
where
    T: Copy,
{
    let ptr = ptr.add(offset) as *const T;
    *ptr
}