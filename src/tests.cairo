use array::ArrayTrait;
use core::result::ResultTrait;
use option::OptionTrait;
use starknet::{class_hash::Felt252TryIntoClassHash, ContractAddress, SyscallResultTrait};
use traits::TryInto;
use identity::{
    identity::main::Identity, interface::identity::{IIdentityDispatcher, IIdentityDispatcherTrait}
};
use verifier::{Verifier, IVerifier, IVerifierDispatcher, IVerifierDispatcherTrait};
use starknet::testing::set_contract_address;
use starknet::contract_address::contract_address_const;

fn deploy(contract_class_hash: felt252, calldata: Array<felt252>) -> ContractAddress {
    let (address, _) = starknet::deploy_syscall(
        contract_class_hash.try_into().unwrap(), 0, calldata.span(), false
    )
        .unwrap_syscall();
    address
}


#[test]
#[available_gas(2000000000)]
fn test_basic_usage() {
    let caller = contract_address_const::<0x123>();
    set_contract_address(caller);

    let identity = IIdentityDispatcher {
        contract_address: deploy(Identity::TEST_CLASS_HASH, array![0, 0])
    };

    // mint id 1
    identity.mint(1);

    // verify something
    let verifier = IVerifierDispatcher {
        contract_address: deploy(
            Verifier::TEST_CLASS_HASH,
            array![
                caller.into(),
                identity.contract_address.into(),
                3571077580641057962019375980836964323430604474979724507958294224671833227961
            ]
        )
    };

    verifier
        .write_confirmation(
            1,
            1717096180,
            32782392107492722,
            707979046952239197,
            (
                184358908201723306707880158438552933229114673950387468604540982997131954128,
                3070140681966331096721750868805285693735076872634770951837263262906056945319
            )
        );
}
