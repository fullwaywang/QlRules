/**
 * @name freerdp-8305349a943c68b1bc8c158f431dc607655aadea-crypto_rsa_common
 * @id cpp/freerdp/8305349a943c68b1bc8c158f431dc607655aadea/crypto-rsa-common
 * @description freerdp-8305349a943c68b1bc8c158f431dc607655aadea-libfreerdp/crypto/crypto.c-crypto_rsa_common CVE-2020-13398
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("malloc")
		and not target_0.getTarget().hasName("calloc")
		and target_0.getArgument(0) instanceof AddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(Initializer target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getExpr().getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Initializer target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getExpr().getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Initializer target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getExpr().getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Initializer target_4 |
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getExpr().getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Initializer target_5 |
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getExpr().getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Initializer target_6 |
		target_6.getExpr().(Literal).getValue()="0"
		and target_6.getExpr().getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Initializer target_7 |
		target_7.getExpr().(Literal).getValue()="0"
		and target_7.getExpr().getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Initializer target_8 |
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getExpr().getEnclosingFunction() = func)
}

predicate func_9(Parameter vmodulus_96, Parameter vexponent_97, Parameter vexponent_size_97, Parameter voutput_97, ExprStmt target_28, ExprStmt target_29, AddExpr target_20, ExprStmt target_30, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vexponent_size_97
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vmodulus_96
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vexponent_97
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=voutput_97
		and target_9.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_9)
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_28.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_20.getAnOperand().(VariableAccess).getLocation())
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_10(Parameter vlength_96, ExprStmt target_26, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_96
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlength_96
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_10))
}

/*predicate func_11(Parameter vlength_96, ExprStmt target_31, ExprStmt target_26) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_11.getRValue().(VariableAccess).getTarget()=vlength_96
		and target_31.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getRValue().(VariableAccess).getLocation()))
}

*/
predicate func_14(Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_14.getThen().(GotoStmt).toString() = "goto ..."
		and target_14.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_14))
}

predicate func_15(Function func) {
	exists(IfStmt target_15 |
		target_15.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_15.getThen().(GotoStmt).toString() = "goto ..."
		and target_15.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_15))
}

predicate func_16(Function func) {
	exists(IfStmt target_16 |
		target_16.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_16.getThen().(GotoStmt).toString() = "goto ..."
		and target_16.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_16 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_16))
}

predicate func_17(Function func) {
	exists(IfStmt target_17 |
		target_17.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_17.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_17.getThen().(GotoStmt).toString() = "goto ..."
		and target_17.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(30)=target_17 or func.getEntryPoint().(BlockStmt).getStmt(30).getFollowingStmt()=target_17))
}

predicate func_18(Variable voutput_length_100, Function func) {
	exists(IfStmt target_18 |
		target_18.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voutput_length_100
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_18.getThen().(GotoStmt).toString() = "goto ..."
		and target_18.getThen().(GotoStmt).getName() ="fail"
		and (func.getEntryPoint().(BlockStmt).getStmt(32)=target_18 or func.getEntryPoint().(BlockStmt).getStmt(32).getFollowingStmt()=target_18))
}

predicate func_20(Parameter vkey_length_96, Parameter vexponent_size_97, AddExpr target_20) {
		target_20.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_20.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vkey_length_96
		and target_20.getAnOperand().(VariableAccess).getTarget()=vexponent_size_97
		and target_20.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_21(Parameter vkey_length_96, Variable vmodulus_reverse_102, Variable vmod_104, FunctionCall target_21) {
		target_21.getTarget().hasName("BN_bin2bn")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vmodulus_reverse_102
		and target_21.getArgument(1).(VariableAccess).getTarget()=vkey_length_96
		and target_21.getArgument(2).(VariableAccess).getTarget()=vmod_104
}

predicate func_22(Parameter vexponent_size_97, Variable vexponent_reverse_103, Variable vexp_104, FunctionCall target_22) {
		target_22.getTarget().hasName("BN_bin2bn")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vexponent_reverse_103
		and target_22.getArgument(1).(VariableAccess).getTarget()=vexponent_size_97
		and target_22.getArgument(2).(VariableAccess).getTarget()=vexp_104
}

predicate func_23(Parameter vlength_96, Variable vinput_reverse_101, Variable vx_104, FunctionCall target_23) {
		target_23.getTarget().hasName("BN_bin2bn")
		and target_23.getArgument(0).(VariableAccess).getTarget()=vinput_reverse_101
		and target_23.getArgument(1).(VariableAccess).getTarget()=vlength_96
		and target_23.getArgument(2).(VariableAccess).getTarget()=vx_104
}

predicate func_24(Variable vctx_99, Variable vmod_104, Variable vexp_104, Variable vx_104, Variable vy_104, FunctionCall target_24) {
		target_24.getTarget().hasName("BN_mod_exp")
		and target_24.getArgument(0).(VariableAccess).getTarget()=vy_104
		and target_24.getArgument(1).(VariableAccess).getTarget()=vx_104
		and target_24.getArgument(2).(VariableAccess).getTarget()=vexp_104
		and target_24.getArgument(3).(VariableAccess).getTarget()=vmod_104
		and target_24.getArgument(4).(VariableAccess).getTarget()=vctx_99
}

predicate func_25(Function func, ExprStmt target_25) {
		target_25.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_25
}

predicate func_26(Function func, ExprStmt target_26) {
		target_26.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_26
}

predicate func_27(Function func, ExprStmt target_27) {
		target_27.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_28(Parameter vkey_length_96, Parameter vmodulus_96, Variable vmodulus_reverse_102, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmodulus_reverse_102
		and target_28.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodulus_96
		and target_28.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vkey_length_96
}

predicate func_29(Parameter vexponent_97, Parameter vexponent_size_97, Variable vexponent_reverse_103, ExprStmt target_29) {
		target_29.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_29.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexponent_reverse_103
		and target_29.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vexponent_97
		and target_29.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexponent_size_97
}

predicate func_30(Parameter voutput_97, Variable voutput_length_100, Variable vy_104, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voutput_length_100
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_bn2bin")
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vy_104
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voutput_97
}

predicate func_31(Parameter vlength_96, Variable vinput_reverse_101, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("crypto_reverse")
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_reverse_101
		and target_31.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_96
}

from Function func, Parameter vlength_96, Parameter vkey_length_96, Parameter vmodulus_96, Parameter vexponent_97, Parameter vexponent_size_97, Parameter voutput_97, Variable vctx_99, Variable voutput_length_100, Variable vinput_reverse_101, Variable vmodulus_reverse_102, Variable vexponent_reverse_103, Variable vmod_104, Variable vexp_104, Variable vx_104, Variable vy_104, FunctionCall target_0, AddExpr target_20, FunctionCall target_21, FunctionCall target_22, FunctionCall target_23, FunctionCall target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_31
where
func_0(func, target_0)
and not func_1(func)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and not func_5(func)
and not func_6(func)
and not func_7(func)
and not func_8(func)
and not func_9(vmodulus_96, vexponent_97, vexponent_size_97, voutput_97, target_28, target_29, target_20, target_30, func)
and not func_10(vlength_96, target_26, func)
and not func_14(func)
and not func_15(func)
and not func_16(func)
and not func_17(func)
and not func_18(voutput_length_100, func)
and func_20(vkey_length_96, vexponent_size_97, target_20)
and func_21(vkey_length_96, vmodulus_reverse_102, vmod_104, target_21)
and func_22(vexponent_size_97, vexponent_reverse_103, vexp_104, target_22)
and func_23(vlength_96, vinput_reverse_101, vx_104, target_23)
and func_24(vctx_99, vmod_104, vexp_104, vx_104, vy_104, target_24)
and func_25(func, target_25)
and func_26(func, target_26)
and func_27(func, target_27)
and func_28(vkey_length_96, vmodulus_96, vmodulus_reverse_102, target_28)
and func_29(vexponent_97, vexponent_size_97, vexponent_reverse_103, target_29)
and func_30(voutput_97, voutput_length_100, vy_104, target_30)
and func_31(vlength_96, vinput_reverse_101, target_31)
and vlength_96.getType().hasName("int")
and vkey_length_96.getType().hasName("UINT32")
and vmodulus_96.getType().hasName("const BYTE *")
and vexponent_97.getType().hasName("const BYTE *")
and vexponent_size_97.getType().hasName("int")
and voutput_97.getType().hasName("BYTE *")
and vctx_99.getType().hasName("BN_CTX *")
and voutput_length_100.getType().hasName("int")
and vinput_reverse_101.getType().hasName("BYTE *")
and vmodulus_reverse_102.getType().hasName("BYTE *")
and vexponent_reverse_103.getType().hasName("BYTE *")
and vmod_104.getType().hasName("BIGNUM *")
and vexp_104.getType().hasName("BIGNUM *")
and vx_104.getType().hasName("BIGNUM *")
and vy_104.getType().hasName("BIGNUM *")
and vlength_96.getParentScope+() = func
and vkey_length_96.getParentScope+() = func
and vmodulus_96.getParentScope+() = func
and vexponent_97.getParentScope+() = func
and vexponent_size_97.getParentScope+() = func
and voutput_97.getParentScope+() = func
and vctx_99.getParentScope+() = func
and voutput_length_100.getParentScope+() = func
and vinput_reverse_101.getParentScope+() = func
and vmodulus_reverse_102.getParentScope+() = func
and vexponent_reverse_103.getParentScope+() = func
and vmod_104.getParentScope+() = func
and vexp_104.getParentScope+() = func
and vx_104.getParentScope+() = func
and vy_104.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
