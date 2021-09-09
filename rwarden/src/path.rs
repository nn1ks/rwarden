//! Module for folder and collection paths.

use std::{borrow::Borrow, iter::FusedIterator, ops::Deref};

#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: std::str::Split<'a, char>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl<'a> FusedIterator for Iter<'a> {}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Path {
    inner: str,
}

impl AsRef<str> for Path {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl AsRef<Path> for str {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for String {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl ToOwned for Path {
    type Owned = PathBuf;

    fn to_owned(&self) -> Self::Owned {
        self.to_path_buf()
    }
}

impl<'a> IntoIterator for &'a Path {
    type Item = &'a str;

    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Path {
    pub fn new<S: AsRef<str> + ?Sized>(s: &S) -> &Path {
        unsafe { &*(s.as_ref() as *const str as *const Path) }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf {
            inner: self.inner.to_owned(),
        }
    }

    pub fn parent(&self) -> Option<&Path> {
        self.inner.rsplit_once('/').map(|v| Self::new(v.0))
    }

    pub fn name(&self) -> &str {
        match self.inner.rsplit_once('/') {
            Some((_, name)) => name,
            None => &self.inner,
        }
    }

    pub fn join<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        let mut buf = self.to_path_buf();
        buf.push(path);
        buf
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.inner.split('/'),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathBuf {
    inner: String,
}

impl Deref for PathBuf {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        Path::new(&self.inner)
    }
}

impl AsRef<Path> for PathBuf {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<str> for PathBuf {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self.deref()
    }
}

impl From<String> for PathBuf {
    fn from(value: String) -> Self {
        Self { inner: value }
    }
}

impl<T: AsRef<str> + ?Sized> From<&T> for PathBuf {
    fn from(value: &T) -> Self {
        Self::new(value.as_ref())
    }
}

impl From<PathBuf> for String {
    fn from(value: PathBuf) -> Self {
        value.inner
    }
}

impl PathBuf {
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self { inner: s.into() }
    }

    pub fn as_path(&self) -> &Path {
        self
    }

    pub fn push<P: AsRef<Path>>(&mut self, path: P) {
        self.inner.push('/');
        self.inner.push_str(path.as_ref().as_str());
    }

    pub fn pop(&mut self) -> Option<String> {
        let idx = self.inner.rfind('/')?;
        let mut name = self.inner.split_off(idx);
        name.remove(0); // Remove leading slash
        Some(name)
    }

    pub fn into_string(self) -> String {
        self.inner
    }
}
