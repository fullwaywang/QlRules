/**
 * @name openssl-5485c56679d7c49b96e8fc8ca708b0b7e7c03c4b-evp_cipher_init_internal
 * @id cpp/openssl/5485c56679d7c49b96e8fc8ca708b0b7e7c03c4b/evp-cipher-init-internal
 * @description openssl-5485c56679d7c49b96e8fc8ca708b0b7e7c03c4b-crypto/evp/evp_enc.c-evp_cipher_init_internal CVE-2022-3358
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcipher_83, Parameter vctx_82, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_4, LogicalAndExpr target_5, LogicalOrExpr target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcipher_83
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="origin"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcipher_83
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcipher_83
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="origin"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctx_82, Parameter vimpl_84, Variable vtmpimpl_90, BlockStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="engine"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtmpimpl_90
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimpl_84
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vctx_82, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="fetched_cipher"
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_2.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_2.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_2.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vcipher_83, Variable vtmpimpl_90, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmpimpl_90
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ENGINE_get_cipher_engine")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="nid"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcipher_83
}

predicate func_4(Parameter vcipher_83, Parameter vctx_82, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcipher_83
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vcipher_83, Parameter vctx_82, LogicalAndExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="engine"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcipher_83
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nid"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcipher_83
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nid"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cipher"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_82
}

from Function func, Parameter vcipher_83, Parameter vctx_82, Parameter vimpl_84, Variable vtmpimpl_90, LogicalOrExpr target_1, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_4, LogicalAndExpr target_5
where
not func_0(vcipher_83, vctx_82, target_2, target_3, target_4, target_5, target_1)
and func_1(vctx_82, vimpl_84, vtmpimpl_90, target_2, target_1)
and func_2(vctx_82, target_2)
and func_3(vcipher_83, vtmpimpl_90, target_3)
and func_4(vcipher_83, vctx_82, target_4)
and func_5(vcipher_83, vctx_82, target_5)
and vcipher_83.getType().hasName("const EVP_CIPHER *")
and vctx_82.getType().hasName("EVP_CIPHER_CTX *")
and vimpl_84.getType().hasName("ENGINE *")
and vtmpimpl_90.getType().hasName("ENGINE *")
and vcipher_83.getParentScope+() = func
and vctx_82.getParentScope+() = func
and vimpl_84.getParentScope+() = func
and vtmpimpl_90.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
