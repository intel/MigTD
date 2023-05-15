pub mod io {
    pub struct IoSliceMut<'a>(&'a mut [u8]);

    #[derive(Clone, Copy)]
    pub struct IoSlice<'a>(&'a [u8]);

    impl<'a> IoSliceMut<'a> {
        pub fn new(buf: &'a mut [u8]) -> Self {
            IoSliceMut(buf)
        }
        pub fn as_slice(&self) -> &[u8] {
            self.0
        }
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            self.0
        }
    }

    impl<'a> IoSlice<'a> {
        pub fn new(buf: &'a [u8]) -> Self {
            IoSlice(buf)
        }

        pub fn as_slice(&self) -> &[u8] {
            self.0
        }
    }
}
