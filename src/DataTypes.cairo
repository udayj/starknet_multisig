%lang starknet

struct Transaction:
    member to: felt
    member function_selector: felt
    member calldata_len: felt
    member calldata: felt*
end

struct Signature:
    member r: felt
    member s: felt
end

struct TxStatus:
    member is_registered: felt
    member is_executed: felt
end