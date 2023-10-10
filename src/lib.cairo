#[starknet::interface]
trait IVerifier<TContractState> {
    fn write_confirmation(
        ref self: TContractState,
        token_id: felt252,
        timestamp: felt252,
        field: felt252,
        data: felt252,
        sig: (felt252, felt252)
    );

    fn upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
}

#[starknet::interface]
trait IStarknetID<TContractState> {
    fn owner_of(self: @TContractState, token_id: felt252) -> starknet::ContractAddress;

    fn set_verifier_data(self: @TContractState, token_id: felt252, field: felt252, data: felt252);
}

#[starknet::contract]
mod Verifier {
    use option::OptionTrait;
    use starknet::ContractAddress;
    use starknet::contract_address::ContractAddressZeroable;
    use starknet::{get_caller_address, get_contract_address, get_block_timestamp};
    use ecdsa::check_ecdsa_signature;
    use starknet::class_hash::ClassHash;
    use super::IStarknetIDDispatcherTrait;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        starknetid_contract: ContractAddress,
        public_key: felt252,
        blacklisted_point: LegacyMap<felt252, bool>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        starknetid_contract: ContractAddress,
        public_key: felt252,
    ) {
        self.admin.write(admin);
        self.starknetid_contract.write(starknetid_contract);
        self.public_key.write(public_key);
    }


    #[external(v0)]
    impl VerifierImpl of super::IVerifier<ContractState> {
        fn write_confirmation(
            ref self: ContractState,
            token_id: felt252,
            timestamp: felt252,
            field: felt252,
            data: felt252,
            sig: (felt252, felt252)
        ) {}

        fn upgrade(ref self: ContractState, new_class_hash: starknet::ClassHash) {
            assert(get_caller_address() == self.admin.read(), 'you are not admin');
            assert(!new_class_hash.is_zero(), 'Class hash cannot be zero');
            starknet::replace_class_syscall(new_class_hash).unwrap();
        }
    }
}
