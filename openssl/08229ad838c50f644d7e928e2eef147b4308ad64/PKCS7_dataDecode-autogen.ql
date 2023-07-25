/**
 * @name openssl-08229ad838c50f644d7e928e2eef147b4308ad64-PKCS7_dataDecode
 * @id cpp/openssl/08229ad838c50f644d7e928e2eef147b4308ad64/PKCS7-dataDecode
 * @description openssl-08229ad838c50f644d7e928e2eef147b4308ad64-PKCS7_dataDecode CVE-2019-1547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vevp_cipher_363) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("EVP_CIPHER_key_length")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vevp_cipher_363)
}

predicate func_2(Variable vetmp_359, Variable vevp_cipher_363) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vevp_cipher_363
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vetmp_359
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BIO_new")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ...")
}

from Function func, Variable vetmp_359, Variable vevp_cipher_363
where
not func_0(vevp_cipher_363)
and vevp_cipher_363.getType().hasName("const EVP_CIPHER *")
and func_2(vetmp_359, vevp_cipher_363)
and vetmp_359.getParentScope+() = func
and vevp_cipher_363.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
