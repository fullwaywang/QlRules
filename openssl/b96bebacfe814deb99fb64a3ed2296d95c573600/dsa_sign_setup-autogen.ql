/**
 * @name openssl-b96bebacfe814deb99fb64a3ed2296d95c573600-dsa_sign_setup
 * @id cpp/openssl/b96bebacfe814deb99fb64a3ed2296d95c573600/dsa-sign-setup
 * @description openssl-b96bebacfe814deb99fb64a3ed2296d95c573600-crypto/dsa/dsa_ossl.c-dsa_sign_setup CVE-2018-0734
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vkq_226, VariableAccess target_0) {
		target_0.getTarget()=vkq_226
}

predicate func_1(Variable vkq_226, AddressOfExpr target_21, VariableAccess target_1) {
		target_1.getTarget()=vkq_226
		and target_1.getLocation().isBefore(target_21.getOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vkq_226, VariableAccess target_2) {
		target_2.getTarget()=vkq_226
}

predicate func_3(Variable vkq_226, VariableAccess target_3) {
		target_3.getTarget()=vkq_226
}

predicate func_4(Variable vkq_226, VariableAccess target_4) {
		target_4.getTarget()=vkq_226
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("BN_init")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_5))
}

predicate func_6(Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("BN_init")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_6))
}

predicate func_7(Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_7))
}

predicate func_8(Variable vk_226, BlockStmt target_22, AddressOfExpr target_23, AddressOfExpr target_15) {
	exists(LogicalOrExpr target_8 |
		target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_set_bit")
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_set_bit")
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_8.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_set_bit")
		and target_8.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_8.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_8.getParent().(IfStmt).getThen()=target_22
		and target_23.getOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_9(Variable vk_226, AddressOfExpr target_23, AddressOfExpr target_15) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("BN_set_bit")
		and target_9.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
		and target_9.getArgument(1).(VariableAccess).getType().hasName("int")
		and target_23.getOperand().(VariableAccess).getLocation().isBefore(target_9.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_9.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_10(Parameter vdsa_222, Variable vkq_226, GotoStmt target_24, EqualityOperation target_14, PointerFieldAccess target_25, AddressOfExpr target_26, AddressOfExpr target_27) {
	exists(LogicalOrExpr target_10 |
		target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_10.getParent().(IfStmt).getThen()=target_24
		and target_14.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_26.getOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_10.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_27.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_11(Variable vkq_226) {
	exists(ConditionalExpr target_11 |
		target_11.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_11.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_11.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_11.getThen().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_11.getElse().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and target_11.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_11.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_11.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof AddressOfExpr)
}

*/
predicate func_12(Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("BN_clear_free")
		and target_12.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_12))
}

predicate func_13(Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("BN_clear_free")
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BIGNUM")
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_13))
}

predicate func_14(Parameter vdsa_222, BlockStmt target_22, EqualityOperation target_14) {
		target_14.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_14.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_14.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_14.getAnOperand().(Literal).getValue()="0"
		and target_14.getParent().(IfStmt).getThen()=target_22
}

predicate func_15(Variable vk_226, Variable vkq_226, AddressOfExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vk_226
		and target_15.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_15.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
}

predicate func_16(Variable vk_226, Variable vK_226, EqualityOperation target_14, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vK_226
		and target_16.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vk_226
		and target_16.getParent().(IfStmt).getCondition()=target_14
}

predicate func_17(Parameter vdsa_222, FunctionCall target_17) {
		target_17.getTarget().hasName("BN_num_bits")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
}

predicate func_18(Parameter vdsa_222, Variable vkq_226, EqualityOperation target_14, RelationalOperation target_19, AddressOfExpr target_27, AddressOfExpr target_21, IfStmt target_18) {
		target_18.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_18.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_18.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_18.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_18.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_18.getThen().(GotoStmt).toString() = "goto ..."
		and target_18.getThen().(GotoStmt).getName() ="err"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_27.getOperand().(VariableAccess).getLocation().isBefore(target_18.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_18.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_21.getOperand().(VariableAccess).getLocation())
}

predicate func_19(Variable vkq_226, BlockStmt target_28, RelationalOperation target_19) {
		 (target_19 instanceof GEExpr or target_19 instanceof LEExpr)
		and target_19.getLesserOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_19.getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_19.getGreaterOperand() instanceof FunctionCall
		and target_19.getParent().(IfStmt).getThen()=target_28
}

predicate func_20(Parameter vdsa_222, Variable vkq_226, RelationalOperation target_19, PointerFieldAccess target_25, AddressOfExpr target_21, ExprStmt target_29, IfStmt target_20) {
		target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
		and target_20.getThen().(GotoStmt).toString() = "goto ..."
		and target_20.getThen().(GotoStmt).getName() ="err"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_21.getOperand().(VariableAccess).getLocation().isBefore(target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_21(Variable vkq_226, AddressOfExpr target_21) {
		target_21.getOperand().(VariableAccess).getTarget()=vkq_226
}

predicate func_22(Variable vkq_226, BlockStmt target_22) {
		target_22.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_22.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
		and target_22.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_22.getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_22.getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="err"
}

predicate func_23(Variable vk_226, AddressOfExpr target_23) {
		target_23.getOperand().(VariableAccess).getTarget()=vk_226
}

predicate func_24(GotoStmt target_24) {
		target_24.toString() = "goto ..."
		and target_24.getName() ="err"
}

predicate func_25(Parameter vdsa_222, PointerFieldAccess target_25) {
		target_25.getTarget().getName()="bn_mod_exp"
		and target_25.getQualifier().(PointerFieldAccess).getTarget().getName()="meth"
		and target_25.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_222
}

predicate func_26(Variable vkq_226, AddressOfExpr target_26) {
		target_26.getOperand().(VariableAccess).getTarget()=vkq_226
}

predicate func_27(Variable vkq_226, AddressOfExpr target_27) {
		target_27.getOperand().(VariableAccess).getTarget()=vkq_226
}

predicate func_28(BlockStmt target_28) {
		target_28.getStmt(0) instanceof IfStmt
}

predicate func_29(Variable vkq_226, Variable vK_226, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vK_226
		and target_29.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkq_226
}

from Function func, Parameter vdsa_222, Variable vk_226, Variable vkq_226, Variable vK_226, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, EqualityOperation target_14, AddressOfExpr target_15, BlockStmt target_16, FunctionCall target_17, IfStmt target_18, RelationalOperation target_19, IfStmt target_20, AddressOfExpr target_21, BlockStmt target_22, AddressOfExpr target_23, GotoStmt target_24, PointerFieldAccess target_25, AddressOfExpr target_26, AddressOfExpr target_27, BlockStmt target_28, ExprStmt target_29
where
func_0(vkq_226, target_0)
and func_1(vkq_226, target_21, target_1)
and func_2(vkq_226, target_2)
and func_3(vkq_226, target_3)
and func_4(vkq_226, target_4)
and not func_5(func)
and not func_6(func)
and not func_7(func)
and not func_8(vk_226, target_22, target_23, target_15)
and not func_10(vdsa_222, vkq_226, target_24, target_14, target_25, target_26, target_27)
and not func_12(func)
and not func_13(func)
and func_14(vdsa_222, target_22, target_14)
and func_15(vk_226, vkq_226, target_15)
and func_16(vk_226, vK_226, target_14, target_16)
and func_17(vdsa_222, target_17)
and func_18(vdsa_222, vkq_226, target_14, target_19, target_27, target_21, target_18)
and func_19(vkq_226, target_28, target_19)
and func_20(vdsa_222, vkq_226, target_19, target_25, target_21, target_29, target_20)
and func_21(vkq_226, target_21)
and func_22(vkq_226, target_22)
and func_23(vk_226, target_23)
and func_24(target_24)
and func_25(vdsa_222, target_25)
and func_26(vkq_226, target_26)
and func_27(vkq_226, target_27)
and func_28(target_28)
and func_29(vkq_226, vK_226, target_29)
and vdsa_222.getType().hasName("DSA *")
and vk_226.getType().hasName("BIGNUM")
and vkq_226.getType().hasName("BIGNUM")
and vK_226.getType().hasName("BIGNUM *")
and vdsa_222.getParentScope+() = func
and vk_226.getParentScope+() = func
and vkq_226.getParentScope+() = func
and vK_226.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
