// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::task::Poll;
use executor::*;

pub mod executor;

pub fn run<T>(future: impl Future<Output = T> + 'static + Send) -> Poll<T>
where
    T: Send + 'static,
{
    EXECUTOR.lock().run(Box::pin(future))
}

pub fn block_on<T>(future: impl Future<Output = T> + 'static + Send) -> T
where
    T: Send + 'static,
{
    EXECUTOR.lock().block_on(Box::pin(future))
}

pub fn add_task<T>(future: impl Future<Output = T> + 'static + Send)
where
    T: Send + 'static,
{
    EXECUTOR.lock().add_task(Box::pin(future))
}

// output: num of tasks in the queue
pub fn poll_tasks() -> usize {
    EXECUTOR.lock().poll_tasks()
}
