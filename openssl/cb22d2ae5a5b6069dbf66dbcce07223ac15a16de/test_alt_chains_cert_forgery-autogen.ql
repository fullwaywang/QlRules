/**
 * @name openssl-cb22d2ae5a5b6069dbf66dbcce07223ac15a16de-test_alt_chains_cert_forgery
 * @id cpp/openssl/cb22d2ae5a5b6069dbf66dbcce07223ac15a16de/test-alt-chains-cert-forgery
 * @description openssl-cb22d2ae5a5b6069dbf66dbcce07223ac15a16de-crypto/x509/verify_extra_test.c-test_alt_chains_cert_forgery CVE-2015-1793
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="24"
		and not target_0.getValue()="2"
		and target_0.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("X509_STORE_CTX_get_error")
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
