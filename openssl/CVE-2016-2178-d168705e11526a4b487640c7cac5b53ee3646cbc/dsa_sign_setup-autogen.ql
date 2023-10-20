/**
 * @name openssl-d168705e11526a4b487640c7cac5b53ee3646cbc-dsa_sign_setup
 * @id cpp/openssl/d168705e11526a4b487640c7cac5b53ee3646cbc/dsa-sign-setup
 * @description openssl-d168705e11526a4b487640c7cac5b53ee3646cbc-crypto/dsa/dsa_ossl.c-dsa_sign_setup CVE-2016-2178
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vk_226, Variable vkq_226, EqualityOperation target_8, IfStmt target_1) {
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(GotoStmt).getName() ="err"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_2(Parameter vdsa_222, Variable vkq_226, EqualityOperation target_8, IfStmt target_2) {
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_2.getThen().(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(GotoStmt).getName() ="err"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_3(Parameter vdsa_222, Variable vkq_226, EqualityOperation target_8, IfStmt target_3) {
		target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="err"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_4(Variable vkq_226, Variable vK_226, EqualityOperation target_8, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vK_226
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_5(Variable vk_226, Variable vK_226, EqualityOperation target_8, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vK_226
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
		and target_5.getParent().(IfStmt).getCondition()=target_8
}

predicate func_6(Variable vk_226, AddressOfExpr target_9, AddressOfExpr target_10, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vk_226
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_6.getOperand().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation())
}

predicate func_7(Parameter vdsa_222, Function func, IfStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_7.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_7.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_7.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_7.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_7.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_7.getElse() instanceof BlockStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(EqualityOperation target_8) {
		target_8.getAnOperand() instanceof BitwiseAndExpr
		and target_8.getAnOperand() instanceof Literal
}

predicate func_9(Variable vk_226, AddressOfExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vk_226
}

predicate func_10(Variable vk_226, AddressOfExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vk_226
}

from Function func, Parameter vdsa_222, Variable vk_226, Variable vkq_226, Variable vK_226, IfStmt target_1, IfStmt target_2, IfStmt target_3, ExprStmt target_4, BlockStmt target_5, AddressOfExpr target_6, IfStmt target_7, EqualityOperation target_8, AddressOfExpr target_9, AddressOfExpr target_10
where
func_1(vk_226, vkq_226, target_8, target_1)
and func_2(vdsa_222, vkq_226, target_8, target_2)
and func_3(vdsa_222, vkq_226, target_8, target_3)
and func_4(vkq_226, vK_226, target_8, target_4)
and func_5(vk_226, vK_226, target_8, target_5)
and func_6(vk_226, target_9, target_10, target_6)
and func_7(vdsa_222, func, target_7)
and func_8(target_8)
and func_9(vk_226, target_9)
and func_10(vk_226, target_10)
and vdsa_222.getType().hasName("DSA *")
and vk_226.getType().hasName("BIGNUM")
and vkq_226.getType().hasName("BIGNUM")
and vK_226.getType().hasName("BIGNUM *")
and vdsa_222.getParentScope+() = func
and vk_226.getParentScope+() = func
and vkq_226.getParentScope+() = func
and vK_226.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
