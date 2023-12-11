#[cfg(test)]
mod tests;

#[starknet::interface]
trait IVerifier<TContractState> {
    fn write_confirmation(
        ref self: TContractState,
        token_id: u128,
        timestamp: u64,
        field: felt252,
        data: felt252,
        sig: (felt252, felt252)
    );

    fn upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
}

#[starknet::contract]
mod Verifier {
    use option::OptionTrait;
    use starknet::ContractAddress;
    use starknet::contract_address::ContractAddressZeroable;
    use starknet::{get_caller_address, get_contract_address, get_block_timestamp};
    use ecdsa::check_ecdsa_signature;
    use starknet::class_hash::ClassHash;
    use identity::interface::identity::{IIdentity, IIdentityDispatcher, IIdentityDispatcherTrait};

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
            token_id: u128,
            timestamp: u64,
            field: felt252,
            data: felt252,
            sig: (felt252, felt252)
        ) {
            let caller = get_caller_address();
            let starknetid_contract = IIdentityDispatcher {
                contract_address: self.starknetid_contract.read()
            };
            let owner = starknetid_contract.owner_from_id(token_id);
            assert(caller == owner, 'Caller is not owner');

            // ensure confirmation is not expired
            assert(get_block_timestamp() <= timestamp, 'Confirmation is expired');

            let (sig_0, sig_1) = sig;
            let is_blacklisted = self.blacklisted_point.read(sig_0);
            assert(!is_blacklisted, 'Signature is blacklisted');

            // blacklisting r should be enough since it depends on the "secure random point" it should never be used again
            // to anyone willing to improve this check in the future, please be careful with s, as (r, -s) is also a valid signature
            self.blacklisted_point.write(sig_0, true);

            let message_hash: felt252 = hash::LegacyHash::hash(
                hash::LegacyHash::hash(hash::LegacyHash::hash(token_id.into(), timestamp), field),
                data
            );
            let public_key = self.public_key.read();
            let is_valid = check_ecdsa_signature(message_hash, public_key, sig_0, sig_1);
            assert(is_valid, 'Invalid signature');

            // writing on Starknet for now, in the future support volition
            starknetid_contract.set_verifier_data(token_id, field, data, 0);
        }

        fn upgrade(ref self: ContractState, new_class_hash: starknet::ClassHash) {
            assert(get_caller_address() == self.admin.read(), 'you are not admin');
            assert(!new_class_hash.is_zero(), 'Class hash cannot be zero');
            starknet::replace_class_syscall(new_class_hash).unwrap();
        }
    }
}
