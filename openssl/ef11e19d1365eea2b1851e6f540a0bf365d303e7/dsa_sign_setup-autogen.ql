/**
 * @name openssl-ef11e19d1365eea2b1851e6f540a0bf365d303e7-dsa_sign_setup
 * @id cpp/openssl/ef11e19d1365eea2b1851e6f540a0bf365d303e7/dsa-sign-setup
 * @description openssl-ef11e19d1365eea2b1851e6f540a0bf365d303e7-crypto/dsa/dsa_ossl.c-dsa_sign_setup CVE-2018-0734
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vk_184, Variable vq_bits_187, FunctionCall target_0) {
		target_0.getTarget().hasName("BN_set_bit")
		and not target_0.getTarget().hasName("BN_is_bit_set")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vk_184
		and target_0.getArgument(1).(VariableAccess).getTarget()=vq_bits_187
}

predicate func_1(Variable vl_185, Variable vm_185, Parameter vdsa_179, LogicalOrExpr target_24, ConditionalExpr target_28, LogicalOrExpr target_23, EqualityOperation target_29, VariableAccess target_1) {
		target_1.getTarget()=vm_185
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_185
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_28.getThen().(VariableAccess).getLocation())
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getLocation())
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_29.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Function func, FunctionCall target_2) {
		target_2.getTarget().hasName("BN_new")
		and not target_2.getTarget().hasName("bn_wexpand")
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vm_185, LogicalOrExpr target_23, VariableAccess target_3) {
		target_3.getTarget()=vm_185
		and target_3.getLocation().isBefore(target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="0"
		and not target_4.getValue()="2"
		and target_4.getParent().(EQExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vl_185, Variable vq_bits_187, FunctionCall target_5) {
		target_5.getTarget().hasName("BN_set_bit")
		and not target_5.getTarget().hasName("bn_get_top")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vl_185
		and target_5.getArgument(1).(VariableAccess).getTarget()=vq_bits_187
}

predicate func_6(Variable vq_bits_187, VariableAccess target_6) {
		target_6.getTarget()=vq_bits_187
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_7(Variable vk_184, Variable vl_185, Variable vm_185, FunctionCall target_7) {
		target_7.getTarget().hasName("BN_copy")
		and not target_7.getTarget().hasName("bn_wexpand")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vk_184
		and target_7.getArgument(1).(ConditionalExpr).getCondition() instanceof RelationalOperation
		and target_7.getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vl_185
		and target_7.getArgument(1).(ConditionalExpr).getElse().(VariableAccess).getTarget()=vm_185
}

predicate func_8(Variable vq_bits_187, VariableAccess target_8) {
		target_8.getTarget()=vq_bits_187
		and target_8.getParent().(GTExpr).getGreaterOperand() instanceof FunctionCall
}

predicate func_9(Variable vm_185, FunctionCall target_9) {
		target_9.getTarget().hasName("BN_clear_free")
		and not target_9.getTarget().hasName("BN_consttime_swap")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vm_185
}

predicate func_11(Parameter vdsa_179, ExprStmt target_31, NotExpr target_32) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(VariableAccess).getType().hasName("int")
		and target_11.getRValue().(FunctionCall).getTarget().hasName("bn_get_top")
		and target_11.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_11.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_32.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_12(Parameter vdsa_179, ExprStmt target_31, NotExpr target_32) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="q"
		and target_12.getQualifier().(VariableAccess).getTarget()=vdsa_179
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(VariableAccess).getLocation())
		and target_12.getQualifier().(VariableAccess).getLocation().isBefore(target_32.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_13(Function func) {
	exists(AddExpr target_13 |
		target_13.getAnOperand().(VariableAccess).getType().hasName("int")
		and target_13.getAnOperand().(Literal).getValue()="2"
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(AddExpr target_14 |
		target_14.getAnOperand().(VariableAccess).getType().hasName("int")
		and target_14.getAnOperand().(Literal).getValue()="2"
		and target_14.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(AddExpr target_15 |
		target_15.getAnOperand().(VariableAccess).getType().hasName("int")
		and target_15.getAnOperand().(Literal).getValue()="2"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Variable vk_184, Variable vl_185, GotoStmt target_33, LogicalOrExpr target_16) {
		target_16.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vk_184
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vl_185
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_16.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_33
}

predicate func_17(Variable vl_185, VariableAccess target_17) {
		target_17.getTarget()=vl_185
		and target_17.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_18(Variable vk_184, VariableAccess target_18) {
		target_18.getTarget()=vk_184
		and target_18.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_19(Variable vl_185, VariableAccess target_19) {
		target_19.getTarget()=vl_185
		and target_19.getParent().(FunctionCall).getParent().(GTExpr).getGreaterOperand() instanceof FunctionCall
}

predicate func_21(Variable vm_185, AssignExpr target_21) {
		target_21.getLValue().(VariableAccess).getTarget()=vm_185
		and target_21.getRValue() instanceof FunctionCall
}

predicate func_22(Variable vm_185, GotoStmt target_33, EqualityOperation target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget()=vm_185
		and target_22.getAnOperand() instanceof Literal
		and target_22.getParent().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_22.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_33
}

predicate func_23(Variable vm_185, Variable vq_bits_187, GotoStmt target_34, LogicalOrExpr target_23) {
		target_23.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_23.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_set_bit")
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vm_185
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_bits_187
		and target_23.getParent().(IfStmt).getThen()=target_34
}

predicate func_24(Variable vk_184, Variable vl_185, Variable vm_185, Parameter vdsa_179, GotoStmt target_35, LogicalOrExpr target_24) {
		target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_185
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vk_184
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_add")
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vm_185
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_185
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="q"
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
		and target_24.getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_24.getParent().(IfStmt).getThen()=target_35
}

predicate func_25(Variable vl_185, Variable vq_bits_187, RelationalOperation target_25) {
		 (target_25 instanceof GTExpr or target_25 instanceof LTExpr)
		and target_25.getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_25.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_185
		and target_25.getLesserOperand().(VariableAccess).getTarget()=vq_bits_187
}

predicate func_26(Variable vl_185, ExprStmt target_36, VariableAccess target_26) {
		target_26.getTarget()=vl_185
		and target_26.getLocation().isBefore(target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_27(Variable vm_185, LogicalOrExpr target_24, VariableAccess target_27) {
		target_27.getTarget()=vm_185
		and target_24.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getLocation())
}

predicate func_28(Variable vl_185, Variable vm_185, ConditionalExpr target_28) {
		target_28.getCondition() instanceof RelationalOperation
		and target_28.getThen().(VariableAccess).getTarget()=vl_185
		and target_28.getElse().(VariableAccess).getTarget()=vm_185
}

predicate func_29(Parameter vdsa_179, EqualityOperation target_29) {
		target_29.getAnOperand().(PointerFieldAccess).getTarget().getName()="bn_mod_exp"
		and target_29.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="meth"
		and target_29.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
		and target_29.getAnOperand().(Literal).getValue()="0"
}

predicate func_31(Variable vq_bits_187, Parameter vdsa_179, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_bits_187
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_31.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
}

predicate func_32(Variable vk_184, Parameter vdsa_179, NotExpr target_32) {
		target_32.getOperand().(FunctionCall).getTarget().hasName("BN_generate_dsa_nonce")
		and target_32.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vk_184
		and target_32.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="q"
		and target_32.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
		and target_32.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="priv_key"
		and target_32.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_179
}

predicate func_33(GotoStmt target_33) {
		target_33.toString() = "goto ..."
		and target_33.getName() ="err"
}

predicate func_34(GotoStmt target_34) {
		target_34.toString() = "goto ..."
		and target_34.getName() ="err"
}

predicate func_35(GotoStmt target_35) {
		target_35.toString() = "goto ..."
		and target_35.getName() ="err"
}

predicate func_36(Variable vl_185, ExprStmt target_36) {
		target_36.getExpr().(FunctionCall).getTarget().hasName("BN_clear_free")
		and target_36.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_185
}

from Function func, Variable vk_184, Variable vl_185, Variable vm_185, Variable vq_bits_187, Parameter vdsa_179, FunctionCall target_0, VariableAccess target_1, FunctionCall target_2, VariableAccess target_3, Literal target_4, FunctionCall target_5, VariableAccess target_6, FunctionCall target_7, VariableAccess target_8, FunctionCall target_9, LogicalOrExpr target_16, VariableAccess target_17, VariableAccess target_18, VariableAccess target_19, AssignExpr target_21, EqualityOperation target_22, LogicalOrExpr target_23, LogicalOrExpr target_24, RelationalOperation target_25, VariableAccess target_26, VariableAccess target_27, ConditionalExpr target_28, EqualityOperation target_29, ExprStmt target_31, NotExpr target_32, GotoStmt target_33, GotoStmt target_34, GotoStmt target_35, ExprStmt target_36
where
func_0(vk_184, vq_bits_187, target_0)
and func_1(vl_185, vm_185, vdsa_179, target_24, target_28, target_23, target_29, target_1)
and func_2(func, target_2)
and func_3(vm_185, target_23, target_3)
and func_4(func, target_4)
and func_5(vl_185, vq_bits_187, target_5)
and func_6(vq_bits_187, target_6)
and func_7(vk_184, vl_185, vm_185, target_7)
and func_8(vq_bits_187, target_8)
and func_9(vm_185, target_9)
and not func_11(vdsa_179, target_31, target_32)
and not func_13(func)
and not func_14(func)
and not func_15(func)
and func_16(vk_184, vl_185, target_33, target_16)
and func_17(vl_185, target_17)
and func_18(vk_184, target_18)
and func_19(vl_185, target_19)
and func_21(vm_185, target_21)
and func_22(vm_185, target_33, target_22)
and func_23(vm_185, vq_bits_187, target_34, target_23)
and func_24(vk_184, vl_185, vm_185, vdsa_179, target_35, target_24)
and func_25(vl_185, vq_bits_187, target_25)
and func_26(vl_185, target_36, target_26)
and func_27(vm_185, target_24, target_27)
and func_28(vl_185, vm_185, target_28)
and func_29(vdsa_179, target_29)
and func_31(vq_bits_187, vdsa_179, target_31)
and func_32(vk_184, vdsa_179, target_32)
and func_33(target_33)
and func_34(target_34)
and func_35(target_35)
and func_36(vl_185, target_36)
and vk_184.getType().hasName("BIGNUM *")
and vl_185.getType().hasName("BIGNUM *")
and vm_185.getType().hasName("BIGNUM *")
and vq_bits_187.getType().hasName("int")
and vdsa_179.getType().hasName("DSA *")
and vk_184.getParentScope+() = func
and vl_185.getParentScope+() = func
and vm_185.getParentScope+() = func
and vq_bits_187.getParentScope+() = func
and vdsa_179.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
