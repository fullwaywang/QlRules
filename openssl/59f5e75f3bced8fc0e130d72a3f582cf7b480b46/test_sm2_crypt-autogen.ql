/**
 * @name openssl-59f5e75f3bced8fc0e130d72a3f582cf7b480b46-test_sm2_crypt
 * @id cpp/openssl/59f5e75f3bced8fc0e130d72a3f582cf7b480b46/test-sm2-crypt
 * @description openssl-59f5e75f3bced8fc0e130d72a3f582cf7b480b46-test_sm2_crypt CVE-2021-3711
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="sm2_plaintext_size(key, digest, ctext_len, &ptext_len)"
		and not target_0.getValue()="sm2_plaintext_size(ctext, ctext_len, &ptext_len)"
		and target_0.getEnclosingFunction() = func)
}

from Function func, Variable vctext_len_149, Variable vptext_len_150, Parameter vdigest_139, Variable vkey_146
where
func_0(func)
and vctext_len_149.getType().hasName("size_t")
and vptext_len_150.getType().hasName("size_t")
and vdigest_139.getType().hasName("const EVP_MD *")
and vkey_146.getType().hasName("EC_KEY *")
and vctext_len_149.getParentScope+() = func
and vptext_len_150.getParentScope+() = func
and vdigest_139.getParentScope+() = func
and vkey_146.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
