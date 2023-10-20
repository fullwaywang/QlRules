/**
 * @name openssl-3681a4558c13198944e6f7f149c4be188e076e14-dsa_sign_setup
 * @id cpp/openssl/3681a4558c13198944e6f7f149c4be188e076e14/dsa-sign-setup
 * @description openssl-3681a4558c13198944e6f7f149c4be188e076e14-crypto/dsa/dsa_ossl.c-dsa_sign_setup CVE-2016-2178
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vk_226, AddressOfExpr target_8, ExprStmt target_9) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(VariableAccess).getTarget()=vk_226
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_0.getOperand().(VariableAccess).getLocation())
		and target_0.getOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdsa_222, Variable vkq_226, NotExpr target_10, PointerFieldAccess target_11, ExprStmt target_5, AddressOfExpr target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_1.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_1.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_1.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_1.getElse() instanceof BlockStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_10.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vk_226, Variable vkq_226, EqualityOperation target_13, IfStmt target_2) {
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
		and target_2.getThen().(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(GotoStmt).getName() ="err"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_3(Parameter vdsa_222, Variable vkq_226, EqualityOperation target_13, IfStmt target_3) {
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(GotoStmt).getName() ="err"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_4(Parameter vdsa_222, Variable vkq_226, EqualityOperation target_13, IfStmt target_4) {
		target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="err"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_5(Variable vkq_226, Variable vK_226, EqualityOperation target_13, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vK_226
		and target_5.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_6(Variable vk_226, Variable vK_226, EqualityOperation target_13, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vK_226
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
		and target_6.getParent().(IfStmt).getCondition()=target_13
}

predicate func_7(Variable vK_226, ExprStmt target_5, VariableAccess target_7) {
		target_7.getTarget()=vK_226
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getLocation())
}

predicate func_8(Variable vk_226, AddressOfExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vk_226
}

predicate func_9(Variable vk_226, Variable vK_226, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vK_226
		and target_9.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
}

predicate func_10(Parameter vdsa_222, Variable vkq_226, NotExpr target_10) {
		target_10.getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_10.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_10.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_10.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_10.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
}

predicate func_11(Parameter vdsa_222, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="bn_mod_exp"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="meth"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
}

predicate func_12(Variable vkq_226, AddressOfExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vkq_226
}

predicate func_13(Parameter vdsa_222, EqualityOperation target_13) {
		target_13.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_13.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_13.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_13.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vdsa_222, Variable vk_226, Variable vkq_226, Variable vK_226, IfStmt target_2, IfStmt target_3, IfStmt target_4, ExprStmt target_5, BlockStmt target_6, VariableAccess target_7, AddressOfExpr target_8, ExprStmt target_9, NotExpr target_10, PointerFieldAccess target_11, AddressOfExpr target_12, EqualityOperation target_13
where
not func_0(vk_226, target_8, target_9)
and not func_1(vdsa_222, vkq_226, target_10, target_11, target_5, target_12, func)
and func_2(vk_226, vkq_226, target_13, target_2)
and func_3(vdsa_222, vkq_226, target_13, target_3)
and func_4(vdsa_222, vkq_226, target_13, target_4)
and func_5(vkq_226, vK_226, target_13, target_5)
and func_6(vk_226, vK_226, target_13, target_6)
and func_7(vK_226, target_5, target_7)
and func_8(vk_226, target_8)
and func_9(vk_226, vK_226, target_9)
and func_10(vdsa_222, vkq_226, target_10)
and func_11(vdsa_222, target_11)
and func_12(vkq_226, target_12)
and func_13(vdsa_222, target_13)
and vdsa_222.getType().hasName("DSA *")
and vk_226.getType().hasName("BIGNUM")
and vkq_226.getType().hasName("BIGNUM")
and vK_226.getType().hasName("BIGNUM *")
and vdsa_222.getParentScope+() = func
and vk_226.getParentScope+() = func
and vkq_226.getParentScope+() = func
and vK_226.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
