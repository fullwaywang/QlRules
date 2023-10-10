/**
 * @name openssl-2198b3a55de681e1f3c23edb0586afe13f438051-aes_ccm_ctrl
 * @id cpp/openssl/2198b3a55de681e1f3c23edb0586afe13f438051/aes-ccm-ctrl
 * @description openssl-2198b3a55de681e1f3c23edb0586afe13f438051-crypto/evp/e_aes.c-aes_ccm_ctrl CVE-2017-3731
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_1945, ExprStmt target_4, ExprStmt target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vlen_1945
		and target_0.getGreaterOperand().(Literal).getValue()="8"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_3, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vcctx_1926, Variable vlen_1945, ExprStmt target_4, ReturnStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof NotExpr
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_1945
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="M"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcctx_1926
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_4.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vc_1924, ExprStmt target_4, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_CTX_encrypting")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1924
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(Variable vcctx_1926, Variable vlen_1945, NotExpr target_3, ExprStmt target_4) {
		target_4.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_1945
		and target_4.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getTarget().getName()="M"
		and target_4.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcctx_1926
		and target_4.getParent().(IfStmt).getCondition()=target_3
}

predicate func_5(Variable vlen_1945, ExprStmt target_5) {
		target_5.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_1945
		and target_5.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="8"
}

predicate func_6(Variable vcctx_1926, ReturnStmt target_6) {
		target_6.getExpr().(PointerFieldAccess).getTarget().getName()="M"
		and target_6.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcctx_1926
}

predicate func_7(Parameter vc_1924, Variable vlen_1945, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(FunctionCall).getTarget().hasName("EVP_CIPHER_CTX_buf_noconst")
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1924
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_7.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vlen_1945
		and target_7.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

from Function func, Parameter vc_1924, Variable vcctx_1926, Variable vlen_1945, NotExpr target_3, ExprStmt target_4, ExprStmt target_5, ReturnStmt target_6, ExprStmt target_7
where
not func_0(vlen_1945, target_4, target_5)
and not func_1(target_3, func)
and not func_2(vcctx_1926, vlen_1945, target_4, target_6, target_7)
and func_3(vc_1924, target_4, target_3)
and func_4(vcctx_1926, vlen_1945, target_3, target_4)
and func_5(vlen_1945, target_5)
and func_6(vcctx_1926, target_6)
and func_7(vc_1924, vlen_1945, target_7)
and vc_1924.getType().hasName("EVP_CIPHER_CTX *")
and vcctx_1926.getType().hasName("EVP_AES_CCM_CTX *")
and vlen_1945.getType().hasName("uint16_t")
and vc_1924.getParentScope+() = func
and vcctx_1926.getParentScope+() = func
and vlen_1945.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
