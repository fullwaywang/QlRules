/**
 * @name openssl-8e20499629b6bcf868d0072c7011e590b5c2294d-rc4_hmac_md5_ctrl
 * @id cpp/openssl/8e20499629b6bcf868d0072c7011e590b5c2294d/rc4-hmac-md5-ctrl
 * @description openssl-8e20499629b6bcf868d0072c7011e590b5c2294d-crypto/evp/e_rc4_hmac_md5.c-rc4_hmac_md5_ctrl CVE-2017-3731
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_214, NotExpr target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_214
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="16"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_CTX_encrypting")
}

predicate func_2(Variable vlen_214, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_214
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_2.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_3(Variable vlen_214, ExprStmt target_3) {
		target_3.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_214
		and target_3.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="16"
}

from Function func, Variable vlen_214, NotExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vlen_214, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vlen_214, target_2)
and func_3(vlen_214, target_3)
and vlen_214.getType().hasName("unsigned int")
and vlen_214.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
