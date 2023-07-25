/**
 * @name openssl-59f5e75f3bced8fc0e130d72a3f582cf7b480b46-pkey_sm2_decrypt
 * @id cpp/openssl/59f5e75f3bced8fc0e130d72a3f582cf7b480b46/pkey-sm2-decrypt
 * @description openssl-59f5e75f3bced8fc0e130d72a3f582cf7b480b46-pkey_sm2_decrypt CVE-2021-3711
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

from Function func, Parameter voutlen_146, Parameter vinlen_147, Variable vec_149, Variable vmd_151
where
voutlen_146.getType().hasName("size_t *")
and vinlen_147.getType().hasName("size_t")
and vec_149.getType().hasName("EC_KEY *")
and vmd_151.getType().hasName("const EVP_MD *")
and voutlen_146.getParentScope+() = func
and vinlen_147.getParentScope+() = func
and vec_149.getParentScope+() = func
and vmd_151.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
