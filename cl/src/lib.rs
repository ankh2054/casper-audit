use std::slice;
use casper_types::{
    account::{Account, AccountHash, ActionThresholds, AssociatedKeys, Weight},
    bytesrepr::{self, Bytes, FromBytes, ToBytes},
    contracts::{ContractPackageStatus, NamedKeys, ContractVersions, EntryPointsMap},
    system::auction::{Bid, Delegator, EraInfo, SeigniorageAllocation},
    AccessRights, CLType, CLTyped, CLValue, Contract, ContractHash, ContractPackage,
    ContractPackageHash, ContractVersionKey, ContractWasmHash, DeployHash, DeployInfo, EntryPoint,
    EntryPointAccess, EntryPointType, EntryPoints, Group, Key, Parameter, ProtocolVersion,
    PublicKey, SecretKey, Transfer, TransferAddr, URef, KEY_HASH_LENGTH, TRANSFER_ADDR_LENGTH,
    U128, U256, U512, UREF_ADDR_LENGTH,
    Signature, ContractWasm, EraId,
};

//fn test_serialize<T>(input_bytes: *const u8, input_size: libc::size_t) -> i32 {
fn test_serialize<T: FromBytes + ToBytes>(input: &[u8]) {
    let res = match T::from_bytes(input) {
        Ok(_v) => _v,
        Err(_e) => return,
    };
    assert!(input.len() > res.1.len());
    let bytes = match T::to_bytes(&res.0) {
        Ok(_v) => _v,
        Err(_e) => panic!("X"),
    };
    let res2 = match T::from_bytes(&bytes) {
        Ok(_v) => _v.0,
        Err(_e) => panic!("Y"),
    };
    return;
}

#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(input_bytes: *const u8, input_size: libc::size_t) -> i32 {
    let input = unsafe { slice::from_raw_parts(input_bytes, input_size) };
    test_serialize::<AccessRights>(input);
    test_serialize::<Account>(input);
    test_serialize::<Bid>(input);
    test_serialize::<Bytes>(input);
    //test_serialize::<CLType>(input);
    test_serialize::<CLValue>(input);
    test_serialize::<Contract>(input);
    test_serialize::<ContractPackage>(input);
    test_serialize::<DeployInfo>(input);
    test_serialize::<EraInfo>(input);
    test_serialize::<Key>(input);
    //test_serialize::<SecretKey>(input);
    test_serialize::<String>(input);
    test_serialize::<Transfer>(input);
    test_serialize::<AccountHash>(input);
    test_serialize::<ActionThresholds>(input);
    test_serialize::<AssociatedKeys>(input);
    test_serialize::<ContractHash>(input);
    test_serialize::<ContractPackageHash>(input);
    test_serialize::<ContractPackageStatus>(input);
    test_serialize::<DeployHash>(input);
    test_serialize::<EntryPointAccess>(input);
    test_serialize::<EntryPoints>(input);
    test_serialize::<EntryPointType>(input);
    test_serialize::<PublicKey>(input);
    test_serialize::<TransferAddr>(input);
    test_serialize::<Weight>(input);
    test_serialize::<ProtocolVersion>(input);
    test_serialize::<NamedKeys>(input);
    test_serialize::<Signature>(input);
    test_serialize::<ContractWasm>(input);
    test_serialize::<ContractVersions>(input);
    test_serialize::<EraId>(input);
    test_serialize::<EntryPointsMap>(input);
    /*
//bool::from_bytes(input);
DictionaryAddr::from_bytes(input);
DisabledVersions::from_bytes(input);
EntryPointsMap::from_bytes(input);
ExecutionEffect::from_bytes(input);
FromBytes::from_bytes(input);
Groups::from_bytes(input);
HashAddr::from_bytes(input);
Key::from_bytes(input);
K::from_bytes(input);
O::from_bytes(input);
OpKind::from_bytes(input);
Self::from_bytes(input);
SemVer::from_bytes(input);
String::from_bytes(input);
T::from_bytes(input);
Transform::from_bytes(input);
URefAddr::from_bytes(input);
URef::from_bytes(input);
Vec::from_bytes(input);
V::from_bytes(input);
*/

    return 0;
}
/*
    b.iter(|| AccessRights::from_bytes(&data));
    b.iter(|| Account::from_bytes(black_box(&account_bytes)).unwrap());
    b.iter(|| BTreeMap::<String, String>::from_bytes(black_box(&data)));
    b.iter(|| Bid::from_bytes(black_box(&bid_bytes)));
    b.iter(|| Bytes::from_bytes(black_box(&data)))
    b.iter(|| Contract::from_bytes(black_box(&contract_bytes)).unwrap());
    b.iter(|| ContractPackage::from_bytes(black_box(&contract_bytes)).unwrap());
    b.iter(|| DeployInfo::from_bytes(&deploy_bytes));
    b.iter(|| EraInfo::from_bytes(&era_info_bytes));
    b.iter(|| Key::from_bytes(black_box(&account_bytes)))
    b.iter(|| Key::from_bytes(black_box(&hash_bytes)))
    b.iter(|| Key::from_bytes(black_box(&uref_bytes)))
    b.iter(|| Option::<u64>::from_bytes(&data));
    b.iter(|| String::from_bytes(&data));
    b.iter(|| Transfer::from_bytes(&transfer_bytes));
    b.iter(|| U128::from_bytes(black_box(&num_u128_bytes)))
    b.iter(|| U256::from_bytes(black_box(&num_u256_bytes)))
    b.iter(|| U512::from_bytes(black_box(&num_u512_bytes)))
    b.iter(|| Vec::<Bytes>::from_bytes(black_box(&data)));
    b.iter(|| Vec::<Key>::from_bytes(black_box(&keys_bytes)));
    b.iter(|| Vec::<String>::from_bytes(&data));
    b.iter(|| i32::from_bytes(black_box(&[0x34, 0x21, 0x40, 0x6c])));
    b.iter(|| u64::from_bytes(black_box(&[0x1e, 0x8b, 0xe1, 0x73, 0x2c, 0xfe, 0x7a, 0xc4])));
    b.iter(|| u8::from_bytes(black_box(&[129u8])));
    let sk = SecretKey::ed25519_from_bytes(sk_bytes).unwrap();
*/
