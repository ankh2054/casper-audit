use std::slice;

use casper_engine_test_support::{
    DeployItemBuilder, ExecuteRequestBuilder, InMemoryWasmTestBuilder, ARG_AMOUNT,
    DEFAULT_ACCOUNT_ADDR, DEFAULT_PAYMENT, DEFAULT_RUN_GENESIS_REQUEST,
};
use casper_types::{contracts::DEFAULT_ENTRY_POINT_NAME, runtime_args, RuntimeArgs};

static mut XBUILDER: Option<InMemoryWasmTestBuilder> = None;

fn xxx() -> InMemoryWasmTestBuilder {
    unsafe {
        if XBUILDER.is_none() {
            let mut builder = InMemoryWasmTestBuilder::default();
            builder
                .run_genesis(&DEFAULT_RUN_GENESIS_REQUEST);
            XBUILDER = Some(builder);
        }
        return XBUILDER.clone().unwrap();
    }
}

#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(input_bytes: *const u8, input_size: libc::size_t) -> i32 {
    let input = unsafe { slice::from_raw_parts(input_bytes, input_size) };
    let deploy_1 = DeployItemBuilder::new()
        .with_address(*DEFAULT_ACCOUNT_ADDR)
        .with_session_bytes(input.to_vec(), RuntimeArgs::new())
        .with_empty_payment_bytes(runtime_args! { ARG_AMOUNT => *DEFAULT_PAYMENT, })
        .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
        .with_deploy_hash([123; 32])
        .build();
    let exec_request_1 = ExecuteRequestBuilder::new().push_deploy(deploy_1).build();
    let mut builder = xxx();
    builder
        .exec(exec_request_1).commit();
    return 0;
}
