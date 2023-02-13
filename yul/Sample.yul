object "Sample" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }

    object "runtime" {
         code {
             requires(iszero(callvalue()))

            function requires(condition) {
                if iszero(condition) { revert(0, 0) }
             }
         }
    }
}