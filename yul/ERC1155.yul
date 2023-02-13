object "ERC1155" {
    code {
        mstore(0x40, 0x80)

        function allocate_unbounded() -> memPtr {
            memPtr := mload(0x40)
        }

        function round_up_to_mul_of_32(value) -> result {
            result := and(add(value, 31), not(31))
        }

        function finalize_allocation(memPtr, size) {
            let newFreePtr := add(memPtr, round_up_to_mul_of_32(size))
            // protect against overflow
            if or(gt(newFreePtr, 0xffffffffffffffff), lt(newFreePtr, memPtr)) { revert(0,0) }
            mstore(64, newFreePtr)
        }

        function allocate_memory(size) -> memPtr {
            memPtr := allocate_unbounded()
            finalize_allocation(memPtr, size)
        }

        function string_storage_slot(ptr) -> data {
            data := ptr

            mstore(0, ptr)
            data := keccak256(0, 0x20)
        }

        function mask_bytes_dynamic(data, bytes) -> result {
            let mask := not(shr(mul(8, bytes), not(0)))
            result := and(data, mask)
        }

        function extract_used_part_and_set_length_of_short_string(data, len) -> used {
            // we want to save only elements that are part of the array after resizing
            // others should be set to zero
            data := mask_bytes_dynamic(data, len)
            used := or(data, mul(2, len))
        }

        function copy_uri_memory_to_storage(slot, headstart, offset) {
            offset := add(headstart, offset)

            let len := mload(offset)

            let srcOffset := 0x20

            switch gt(len, 31)
            case 1 {
                let loopEnd := and(len, not(0x1f))
                let dstPtr := string_storage_slot(slot)

                let i := 0
                for { } lt(i, loopEnd) { i := add(i, 0x20) } {
                    sstore(dstPtr, mload(add(offset, srcOffset)))
                    dstPtr := add(dstPtr, 1)
                    srcOffset := add(srcOffset, 32)
                }
                if lt(loopEnd, len) {
                    let lastValue := mload(add(offset, srcOffset))
                    sstore(dstPtr, mask_bytes_dynamic(lastValue, and(len, 0x1f)))
                }
                sstore(slot, add(mul(len, 2), 1))
            }
            default {
                let value := 0
                if len {
                    value := mload(add(offset, srcOffset))
                }
                sstore(slot, extract_used_part_and_set_length_of_short_string(value, len))
            }
        }

        let programSize := datasize("ERC1155")
        let argSize := sub(codesize(), programSize)

        let memoryDataOffset := allocate_memory(argSize)

        codecopy(memoryDataOffset, programSize, argSize)

        copy_uri_memory_to_storage(0x02, memoryDataOffset, mload(memoryDataOffset))

        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }

    object "runtime" {
        code {
            requires(iszero(callvalue()))
            mstore(0x40, 0x80)

            switch selector()
            case 0x00fdd58e /* "balanceOf(address,uint256)" */{
                returnUint(balanceOf(decodeAsAddress(0), decodeAsUint(1)))
            }
            case 0x4e1273f4 /* "balanceOfBatch(address[],uint256[])" */ {
                let offset := balanceOfBatch(decodeAsUintMemoryArray(0), decodeAsUintMemoryArray(1))
                let length := mload(offset)
                return(offset, add(0x20, mul(0x20, length)))
            }
            case 0xe985e9c5 /* isApprovedForAll(address,address) */ {
                //returnTrue()
                returnUint(isApprovedForAll(decodeAsAddress(0), decodeAsAddress(1)))
            }
            case 0x731133e9 /* mint(address,uint256,uint256,bytes) */ {
                mint(decodeAsAddress(0), decodeAsUint(1), decodeAsUint(2), decodeAsMemoryBytes(3))
            }
            case 0xb48ab8b6 /* batchMint(address,uint256[],uint256[],bytes) */ {
                batchMint(decodeAsAddress(0), decodeAsUintMemoryArray(1), decodeAsUintMemoryArray(2), decodeAsMemoryBytes(3))
            }
            case 0xf5298aca /* burn(address,uint256,uint256) */ {
                burn(decodeAsAddress(0), decodeAsUint(1), decodeAsUint(2))
            }
            case 0xf6eb127a /* batchBurn(address,uint256[],uint256[]) */ {
                batchBurn(decodeAsAddress(0), decodeAsUintMemoryArray(1), decodeAsUintMemoryArray(2))
            }
            case 0x2eb2c2d6 /* safeBatchTransferFrom(address,address,uint256[],uint256[],bytes) */ {
                safeBatchTransferFrom(decodeAsAddress(0), decodeAsAddress(1), decodeAsUintMemoryArray(2), decodeAsUintMemoryArray(3), decodeAsMemoryBytes(4))
            }
            case 0xf242432a /* safeTransferFrom(address,address,uint256,uint256,bytes) */ {
                safeTransferFrom(decodeAsAddress(0), decodeAsAddress(1), decodeAsUint(2), decodeAsUint(3), decodeAsMemoryBytes(4))
            }
            case 0xa22cb465 /* setApprovalForAll(address,bool) */ {
                setApprovalForAll(decodeAsAddress(0), decodeAsUint(1))
                returnTrue()
            }
            case 0x0e89341c /* uri(uint256) */ {
                let uriPtr := uri(decodeAsUint(0))
                let length := mload(add(uriPtr, 0x20))
                //return(add(uriPtr, 0x20), add(0x20,length))
                return(uriPtr, add(0x40, length))
            }
            default { 
                revert(0,0)
            }

            function uri(id) -> uriPtr {
                uriPtr := allocate_unbounded()
                mstore(uriPtr, 0x20)
                let end := copy_string_storage_to_memory(0x02, add(uriPtr, 0x20))
                finalize_allocation(uriPtr, sub(end, uriPtr))
            }

            function safeBatchTransferFrom(from, to, ids, amounts, data) {
                revertIfZeroAddress(to)

                let ids_length := mload(ids)
                let amounts_length := mload(amounts)

                requires(eq(ids_length, amounts_length))

                let operator := caller()

                for {let i := 1} lte(i, ids_length) { i := add(i, 1)} 
                {
                    let id_offset := add(ids, mul(i, 0x20))
                    let id := mload(id_offset)
                    let amount_offset := add(amounts, mul(i, 0x20))
                    let amount := mload(amount_offset)

                    deductFromBalance(id, from, amount)
                    addToBalance(id, to, amount)
                }

                emitTransferBatch(operator, from, to, ids, amounts)

                doSafeBatchTransferAcceptanceCheck(operator, from, to, ids, amounts, data)
            }

            function safeTransferFrom(from, to, id, amount, data) {
                requires(or(eq(from, caller()), isApprovedForAll(from, caller())))
                revertIfZeroAddress(to)

                let operator := caller()

                deductFromBalance(id, from, amount)
                addToBalance(id, to, amount)

                emitTransferSingle(operator, from, to, id, amount)

                doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data)
            }

            function mint(to, id, amount, data) {
                revertIfZeroAddress(to)

                let operator := caller()

                addToBalance(id, to, amount)

                emitTransferSingle(operator, 0x0, to, id, amount)

                doSafeTransferAcceptanceCheck(operator, 0x0, to, id, amount, data)
            }

            function batchMint(to, ids, amounts, data) {
                revertIfZeroAddress(to)

                let ids_length := mload(ids)
                let amounts_length := mload(amounts)

                requires(eq(ids_length, amounts_length))

                let operator := caller()

                for {let i := 1} lte(i, ids_length) { i := add(i, 1)} {
                    let id := mload(add(ids, mul(i, 0x20)))
                    let amount := mload(add(amounts, mul(i,0x20)))

                    mint(to, id, amount, data)
                }

                emitTransferBatch(operator, 0x0, to, ids, amounts)

                doSafeBatchTransferAcceptanceCheck(operator, 0x0, to, ids, amounts, data)
            }

            function burn(from, id, amount) {
                revertIfZeroAddress(from)

                deductFromBalance(id, from, amount)

                emitTransferSingle(caller(), from, 0x0, id, amount)
            }

            function batchBurn(from, ids, amounts) {
                revertIfZeroAddress(from)

                let ids_length := mload(ids)
                let amounts_length := mload(amounts)

                requires(eq(ids_length, amounts_length))

                for {let i := 1} lte(i, ids_length) { i := add(i, 1)} 
                {
                    let id_offset := add(ids, mul(i, 0x20))
                    let id := mload(id_offset)
                    let amount_offset := add(amounts, mul(i, 0x20))
                    let amount := mload(amount_offset)

                    deductFromBalance(id, from, amount)
                }

                //emitTransferBatch(caller(), from, 0x0, ids, amounts)
            }

            function beforeTokenTransfer(
                operator,
                from,
                to,
                ids,
                amounts,
                data
            ) {}

            function afterTokenTransfer(
                operator,
                from,
                to,
                ids,
                amounts,
                data
            ) {}

            function doSafeTransferAcceptanceCheck(
                operator,
                from,
                to,
                id,
                amount,
                data
            ) {
                if extcodesize(to) {
                    let fun_selector := 0xf23a6e61
                    let ptr := allocate_unbounded()
                    mstore(ptr, shl(224, fun_selector))
                    let headStart := add(ptr, 4)
                    mstore(add(headStart, 0), operator)
                    mstore(add(headStart, 32), from)
                    mstore(add(headStart, 64), id)
                    mstore(add(headStart, 96), amount)

                    let tail := add(headStart, 160)

                    mstore(add(headStart, 128), sub(tail, headStart))
                    let data_len := mload(data)
                    mstore(tail, data_len)

                    tail := add(tail, 0x20)

                    for {let i := 0} lt(i, data_len) { i := add(i,0x20)} {
                        let data_chunk := mload(add(add(data, 0x20), i))
                        mstore(tail, data_chunk)
                        tail := add(tail, 0x20)
                    } 

                    let success := call(gas(), to, 0, ptr, sub(tail, ptr), ptr, 32)
                    if iszero(success) { revert(0,0) }

                    finalize_allocation(ptr, returndatasize())

                    let return_data := mload(ptr)
                    requires(eq(return_data, 0xf23a6e6100000000000000000000000000000000000000000000000000000000))
                }
            }

            function doSafeBatchTransferAcceptanceCheck(
                operator,
                from,
                to,
                ids,
                amounts,
                data
            ) {
                if extcodesize(to) {
                    let fun_selector := 0xbc197c81
                    let ptr := allocate_unbounded()
                    mstore(ptr, shl(224, fun_selector))
                    let headStart := add(ptr, 4)
                    mstore(add(headStart, 0), operator)
                    mstore(add(headStart, 32), from)

                    let tail := add(headStart, 160)

                    mstore(add(headStart, 64), sub(tail, headStart))
                    let ids_len := mload(ids)
                    mstore(tail, ids_len)
                    tail := add(tail, 0x20)

                    for {let i := 0} lt(i, ids_len) { i := add(i,1)} {
                        let id := mload(add(add(ids, 0x20), mul(i, 0x20)))
                        mstore(tail, id)
                        tail := add(tail, 0x20)
                    } 

                    mstore(add(headStart, 96), sub(tail, headStart))
                    let amounts_len := mload(amounts)
                    mstore(tail, amounts_len)
                    tail := add(tail, 0x20)

                    for {let i := 0} lt(i, amounts_len) { i := add(i,1)} {
                        let amount := mload(add(add(amounts, 0x20), mul(i, 0x20)))
                        mstore(tail, amount)
                        tail := add(tail, 0x20)
                    } 

                    mstore(add(headStart, 128), sub(tail, headStart))
                    let data_len := mload(data)
                    mstore(tail, data_len)

                    tail := add(tail, 0x20)

                    for {let i := 0} lt(i, data_len) { i := add(i,0x20)} {
                        let data_chunk := mload(add(add(data, 0x20), i))
                        mstore(tail, data_chunk)
                        tail := add(tail, 0x20)
                    } 

                    let success := call(gas(), to, 0, ptr, sub(tail, ptr), ptr, 32)
                    if iszero(success) { revert(0,0) }

                    finalize_allocation(ptr, returndatasize())

                    let return_data := mload(ptr)
                    requires(eq(return_data, 0xbc197c8100000000000000000000000000000000000000000000000000000000))
                }
            }

            /* ------- memory operations ---------*/

            function copy_calldata_to_memory_with_cleanup(src, dst, length) {
                calldatacopy(dst, src, length)
                mstore(add(dst, length), 0)
            }

            function round_up_to_mul_of_32(value) -> result {
                result := and(add(value, 31), not(31))
            }

            function allocate_unbounded() -> memPtr {
                memPtr := mload(0x40)
            }

            function finalize_allocation(memPtr, size) {
                let newFreePtr := add(memPtr, round_up_to_mul_of_32(size))
                // protect against overflow
                if or(gt(newFreePtr, 0xffffffffffffffff), lt(newFreePtr, memPtr)) { revert(0, 0) }
                mstore(0x40, newFreePtr)
            }

            function allocate_memory(size) -> memPtr {
                memPtr := allocate_unbounded()
                finalize_allocation(memPtr, size)
            }

            function allocate_memory_array(length) -> memPtr {
                let size := mul(length, 0x20)
                size := add(size, 0x20)
                memPtr := allocate_memory(size)
            }
            
            /* ---------- calldata decoding functions ----------- */
            function selector() -> s {
                s := div(calldataload(0), 0x100000000000000000000000000000000000000000000000000000000)
            }

            function decodeAsAddress(offset) -> v {
                v := decodeAsUint(offset)
                if iszero(iszero(and(v, not(0xffffffffffffffffffffffffffffffffffffffff)))) {
                    revert(0, 0)
                }
            }
            function decodeAsUint(offset) -> v {
                let pos := add(4, mul(offset, 0x20))
                if lt(calldatasize(), add(pos, 0x20)) {
                    revert(0, 0)
                }
                v := calldataload(pos)
            }

            function decodeAsUintMemoryArray(offset) -> ptr {
                let lengthOffset := add(4, decodeAsUint(offset))
                let length := calldataload(lengthOffset)

                ptr := allocate_unbounded()

                let arrayOffset := add(lengthOffset, 0x20)
                mstore(ptr, length)
                calldatacopy(add(ptr, 0x20), arrayOffset, mul(length, 0x20))

                finalize_allocation(ptr, add(0x20, mul(length,0x20)))
            }

            function decodeAsMemoryBytes(offset) -> ptr {
                let pos := decodeAsUint(offset)
                pos := add(4, pos)
                let length := calldataload(pos)
                let memSize := round_up_to_mul_of_32(length)

                // add length slot
                memSize := add(memSize, 0x20)

                ptr := allocate_memory(memSize)

                let src := pos
                let dst := ptr

                copy_calldata_to_memory_with_cleanup(src, dst, add(length, 0x20))
            }

            function getArrayElementFromCalldataIndex(base_ref, index) -> elem {
                let addr := add(base_ref, mul(index, 0x20))
                elem := calldataload(addr)
            }

            function extract_byte_array_length(data) -> length {
                length := div(data, 2)
                let outOfPlaceEncoding := and(data, 1)
                if iszero(outOfPlaceEncoding) {
                    length := and(length, 0x7f)
                }

                if eq(outOfPlaceEncoding, lt(length, 32)) {
                    revert(0,0)
                }
            }

            function copy_string_storage_to_memory(slot, memPtr) -> end {
                let slotValue := sload(slot)
                let length := extract_byte_array_length(slotValue)
                mstore(memPtr, length)
                memPtr := add(memPtr, 0x20)

                switch and(slotValue, 1)
                case 0 {
                    // short byte array
                    mstore(memPtr, and(slotValue, not(0xff)))
                    end := add(memPtr, mul(0x20, iszero(iszero(length))))
                }
                case 1 {
                    // long byte array
                    let dataPos := string_storage_slot(slot)
                    let i := 0
                    for { } lt(i, length) { i := add(i, 0x20) } {
                        mstore(add(memPtr, i), sload(dataPos))
                        dataPos := add(dataPos, 1)
                    }
                    end := add(memPtr, i)
                }
            }

            /* ---------- calldata encoding functions ---------- */
            function returnUint(v) {
                mstore(0, v)
                return(0, 0x20)
            }

            function returnTrue() {
                returnUint(1)
            }

            function toSingletonArray(value) -> ptr{
                ptr := mload(0x40)
                mstore(ptr, 0x1)
                mstore(add(ptr,0x20), value)
                mstore(0x40, add(ptr, 0x40))
            }



            /*---------------- events -------------------*/

            function emitTransferSingle(operator, from, to, id, amount) {
                let signatureHash := 0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62
                let ptr := allocate_memory(0x40)
                mstore(ptr, id)
                mstore(add(ptr, 0x20), amount)
                log4(ptr, 0x40, signatureHash, operator, from, to)
            }

            function emitTransferBatch(operator, from, to, ids, amounts) {
                let signatureHash := 0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb
                let ids_len := mload(ids)
                let memSize := add(0x40, mul(ids_len, 2))
                log4(ids, memSize, signatureHash, operator, from, to)
            }

            function emitApprovalForAll(owner, operator, approved) {
                let signatureHash := 0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31
                let ptr := allocate_memory(0x20)
                mstore(ptr, approved)
                log3(ptr, 0x20, signatureHash, owner, operator)
            }

            function emitURI(value, id) {
                let signatureHash := 0x6bb7ff708619ba0610cba295a58592e0451dee2622938c8755667688daf3529b
            }

            /* -------- storage layout ---------- */
            function idToStorageOffset(id) -> offset {
                offset := add(0x1000, id)
            }
            function idToAccountStorageOffset(id, account) -> offset {
                offset := idToStorageOffset(id)
                mstore(0, offset)
                mstore(0x20, account)
                offset := keccak256(0, 0x40)
            }
            function accountToStorageOffset(account) -> offset {
                offset := add(0x2000, account)
            }
            function accountToOperatorOffset(account, operator) -> offset {
                offset := accountToStorageOffset(account)
                mstore(0, offset)
                mstore(0x20, operator)
                offset := keccak256(0, 0x40)
            }
            function string_storage_slot(ptr) -> data {
                mstore(0, ptr)
                data := keccak256(0, 0x20)
            }

            /*--------------storage access-----------------*/
            function balanceOf(account, id) -> _balance {
                revertIfZeroAddress(account)
                let offset := idToAccountStorageOffset(id, account)
                _balance := sload(offset)
            }

            function balanceOfBatch(accounts, ids) -> ptr {
                let account_length := mload(accounts)
                let ids_length := mload(ids)

                requires(eq(account_length,ids_length))

                ptr := allocate_memory(0x20)
                mstore(ptr, 0x20)

                let batchBalances := allocate_memory_array(account_length)

                mstore(batchBalances, account_length)

                for {let i:= 1} lte(i, account_length) {i := add(i, 1)} {
                    let account := mload(add(accounts, mul(i, 0x20)))
                    let id := mload(add(ids, mul(i, 0x20)))

                    let _balance := balanceOf(account, id)

                    mstore(add(batchBalances, mul(i, 0x20)), _balance)
                }
            }

            function addToBalance(id, account, amount) {
                let offset := idToAccountStorageOffset(id, account)
                let updatedBalance := safeAdd(sload(offset), amount)
                sstore(offset, updatedBalance) 
            }

            function deductFromBalance(id, account, amount) {
                let offset := idToAccountStorageOffset(id, account)
                let bal := sload(offset)
                requires(lte(amount, bal))
                sstore(offset, sub(bal, amount))
            }

            function setApprovalForAll(operator, approved) {
                requires(not(eq(caller(), operator)))
                let offset := accountToOperatorOffset(caller(), operator)
                sstore(offset, approved)
            }

            function isApprovedForAll(account, operator) -> approved {
                let offset := accountToOperatorOffset(account, operator)
                approved := sload(offset)
            }

            /* ---------- utility functions ---------- */
            function lte(a, b) -> r {
                r := iszero(gt(a, b))
            }
            function gte(a, b) -> r {
                r := iszero(lt(a, b))
            }
            function safeAdd(a, b) -> r {
                r := add(a, b)
                if or(lt(r, a), lt(r, b)) { revert(0, 0) }
            }

            function revertIfZeroAddress(addr) {
                requires(addr)
            }
            
            function requires(condition) {
                if iszero(condition) { revert(0, 0) }
            }
        }
    }
}