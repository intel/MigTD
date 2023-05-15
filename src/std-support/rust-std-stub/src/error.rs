//! Traits for working with Errors.

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string;
use alloc::string::String;
use core::any::TypeId;
use core::array;
use core::cell;
use core::char;
use core::convert::Infallible;
use core::fmt::{self, Debug, Display};
use core::num;
use core::str;

pub trait Error: Debug + Display {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn type_id(&self, _: private::Internal) -> TypeId
    where
        Self: 'static,
    {
        TypeId::of::<Self>()
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}

mod private {
    // This is a hack to prevent `type_id` from being overridden by `Error`
    // implementations, since that can enable unsound downcasting.

    #[derive(Debug)]
    pub struct Internal;
}

impl<'a, E: Error + 'a> From<E> for Box<dyn Error + 'a> {
    fn from(err: E) -> Box<dyn Error + 'a> {
        Box::new(err)
    }
}

impl<'a, E: Error + Send + Sync + 'a> From<E> for Box<dyn Error + Send + Sync + 'a> {
    fn from(err: E) -> Box<dyn Error + Send + Sync + 'a> {
        Box::new(err)
    }
}

impl From<String> for Box<dyn Error + Send + Sync> {
    #[inline]
    fn from(err: String) -> Box<dyn Error + Send + Sync> {
        struct StringError(String);

        impl Error for StringError {
            #[allow(deprecated)]
            fn description(&self) -> &str {
                &self.0
            }
        }

        impl Display for StringError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Display::fmt(&self.0, f)
            }
        }

        // Purposefully skip printing "StringError(..)"
        impl Debug for StringError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Debug::fmt(&self.0, f)
            }
        }

        Box::new(StringError(err))
    }
}

impl From<String> for Box<dyn Error> {
    /// Converts a [`String`] into a box of dyn [`Error`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    /// use std::mem;
    ///
    /// let a_string_error = "a string error".to_string();
    /// let a_boxed_error = Box::<dyn Error>::from(a_string_error);
    /// assert!(mem::size_of::<Box<dyn Error>>() == mem::size_of_val(&a_boxed_error))
    /// ```
    fn from(str_err: String) -> Box<dyn Error> {
        let err1: Box<dyn Error + Send + Sync> = From::from(str_err);
        let err2: Box<dyn Error> = err1;
        err2
    }
}

impl<'a> From<&str> for Box<dyn Error + Send + Sync + 'a> {
    /// Converts a [`str`] into a box of dyn [`Error`] + [`Send`] + [`Sync`].
    ///
    /// [`str`]: prim@str
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    /// use std::mem;
    ///
    /// let a_str_error = "a str error";
    /// let a_boxed_error = Box::<dyn Error + Send + Sync>::from(a_str_error);
    /// assert!(
    ///     mem::size_of::<Box<dyn Error + Send + Sync>>() == mem::size_of_val(&a_boxed_error))
    /// ```
    #[inline]
    fn from(err: &str) -> Box<dyn Error + Send + Sync + 'a> {
        From::from(String::from(err))
    }
}

impl From<&str> for Box<dyn Error> {
    /// Converts a [`str`] into a box of dyn [`Error`].
    ///
    /// [`str`]: prim@str
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    /// use std::mem;
    ///
    /// let a_str_error = "a str error";
    /// let a_boxed_error = Box::<dyn Error>::from(a_str_error);
    /// assert!(mem::size_of::<Box<dyn Error>>() == mem::size_of_val(&a_boxed_error))
    /// ```
    fn from(err: &str) -> Box<dyn Error> {
        From::from(String::from(err))
    }
}

impl<'a, 'b> From<Cow<'b, str>> for Box<dyn Error + Send + Sync + 'a> {
    /// Converts a [`Cow`] into a box of dyn [`Error`] + [`Send`] + [`Sync`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    /// use std::mem;
    /// use std::borrow::Cow;
    ///
    /// let a_cow_str_error = Cow::from("a str error");
    /// let a_boxed_error = Box::<dyn Error + Send + Sync>::from(a_cow_str_error);
    /// assert!(
    ///     mem::size_of::<Box<dyn Error + Send + Sync>>() == mem::size_of_val(&a_boxed_error))
    /// ```
    fn from(err: Cow<'b, str>) -> Box<dyn Error + Send + Sync + 'a> {
        From::from(String::from(err))
    }
}

impl<'a> From<Cow<'a, str>> for Box<dyn Error> {
    /// Converts a [`Cow`] into a box of dyn [`Error`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::error::Error;
    /// use std::mem;
    /// use std::borrow::Cow;
    ///
    /// let a_cow_str_error = Cow::from("a str error");
    /// let a_boxed_error = Box::<dyn Error>::from(a_cow_str_error);
    /// assert!(mem::size_of::<Box<dyn Error>>() == mem::size_of_val(&a_boxed_error))
    /// ```
    fn from(err: Cow<'a, str>) -> Box<dyn Error> {
        From::from(String::from(err))
    }
}

impl Error for str::ParseBoolError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "failed to parse bool"
    }
}

impl Error for str::Utf8Error {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "invalid utf-8: corrupt contents"
    }
}

impl Error for num::ParseIntError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        // self.__description()
        ""
    }
}

impl Error for num::TryFromIntError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        // self.__description()
        ""
    }
}

impl Error for array::TryFromSliceError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        ""
        // self.__description()
    }
}

impl Error for num::ParseFloatError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        ""
        // self.__description()
    }
}

impl Error for string::FromUtf8Error {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "invalid utf-8"
    }
}

impl Error for string::FromUtf16Error {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "invalid utf-16"
    }
}

impl Error for Infallible {
    fn description(&self) -> &str {
        match *self {}
    }
}

impl Error for char::DecodeUtf16Error {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "unpaired surrogate found"
    }
}

impl<T: Error> Error for Box<T> {
    #[allow(deprecated, deprecated_in_future)]
    fn description(&self) -> &str {
        Error::description(&**self)
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn Error> {
        Error::cause(&**self)
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Error::source(&**self)
    }
}

impl Error for fmt::Error {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "an error occurred when formatting an argument"
    }
}

impl Error for cell::BorrowError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "already mutably borrowed"
    }
}

impl Error for cell::BorrowMutError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "already borrowed"
    }
}

impl Error for char::CharTryFromError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "converted integer out of range for `char`"
    }
}

impl Error for char::ParseCharError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        // self.__description()
        ""
    }
}

// impl Error for alloc::collections::TryReserveError {}

// Copied from `any.rs`.
impl dyn Error + 'static {
    /// Returns `true` if the boxed type is the same as `T`
    #[inline]
    pub fn is<T: Error + 'static>(&self) -> bool {
        // Get `TypeId` of the type this function is instantiated with.
        let t = TypeId::of::<T>();

        // Get `TypeId` of the type in the trait object.
        let boxed = self.type_id(private::Internal);

        // Compare both `TypeId`s on equality.
        t == boxed
    }
}

impl dyn Error + 'static + Send {
    /// Forwards to the method defined on the type `dyn Error`.
    #[inline]
    pub fn is<T: Error + 'static>(&self) -> bool {
        <dyn Error + 'static>::is::<T>(self)
    }
}

impl dyn Error + 'static + Send + Sync {
    /// Forwards to the method defined on the type `dyn Error`.
    #[inline]
    pub fn is<T: Error + 'static>(&self) -> bool {
        <dyn Error + 'static>::is::<T>(self)
    }
}

impl dyn Error {
    #[inline]
    pub fn chain(&self) -> Chain<'_> {
        Chain {
            current: Some(self),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Chain<'a> {
    current: Option<&'a (dyn Error + 'static)>,
}

impl<'a> Iterator for Chain<'a> {
    type Item = &'a (dyn Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        self.current = self.current.and_then(Error::source);
        current
    }
}

impl dyn Error + Send {}

impl dyn Error + Send + Sync {}
