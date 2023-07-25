/**
 * @name openssl-d73cc256c8e256c32ed959456101b73ba9842f72-test_mod_exp
 * @id cpp/openssl/d73cc256c8e256c32ed959456101b73ba9842f72/test-mod-exp
 * @description openssl-d73cc256c8e256c32ed959456101b73ba9842f72-crypto/bn/bntest.c-test_mod_exp CVE-2015-3193
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable va_974, ExprStmt target_6, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("BN_hex2bn")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=va_974
		and target_0.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="050505050505"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vb_974, NotExpr target_7, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("BN_hex2bn")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vb_974
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="02"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_1)
		and target_7.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vc_974, ExprStmt target_6, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("BN_hex2bn")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vc_974
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="414141414141414141414127414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2)
		and target_6.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vctx_972, Variable va_974, Variable vb_974, Variable vc_974, Variable vd_974, ExprStmt target_6, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("BN_mod_exp")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_974
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va_974
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vb_974
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vc_974
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx_972
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_3)
		and target_6.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vctx_972, Variable va_974, Variable ve_974, ExprStmt target_11, ExprStmt target_6, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("BN_mul")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ve_974
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va_974
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=va_974
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_972
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_4)
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Variable vd_974, Variable ve_974, Variable vstderr, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(FunctionCall).getTarget().hasName("BN_cmp")
		and target_5.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_974
		and target_5.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_974
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="BN_mod_exp and BN_mul produce different results!\n"
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_5)
		and target_5.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vctx_972, Variable va_974, Variable vb_974, Variable vc_974, Variable ve_974, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("BN_div")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_974
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vb_974
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=ve_974
		and target_6.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vc_974
		and target_6.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx_972
}

predicate func_7(Variable vb_974, NotExpr target_7) {
		target_7.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_7.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_974
		and target_7.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vb_974, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("BN_free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vb_974
}

predicate func_9(Variable vc_974, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("BN_free")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_974
}

predicate func_10(Variable vd_974, Variable ve_974, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("BN_sub")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ve_974
		and target_10.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_974
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vd_974
}

predicate func_11(Variable va_974, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("BN_free")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_974
}

predicate func_12(Variable vd_974, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("BN_free")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vd_974
}

predicate func_13(Variable ve_974, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("BN_free")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ve_974
}

predicate func_14(Variable vstderr, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_14.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Modulo exponentiation test failed!\n"
}

from Function func, Parameter vctx_972, Variable va_974, Variable vb_974, Variable vc_974, Variable vd_974, Variable ve_974, Variable vstderr, ExprStmt target_6, NotExpr target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14
where
not func_0(va_974, target_6, func)
and not func_1(vb_974, target_7, func)
and not func_2(vc_974, target_6, func)
and not func_3(vctx_972, va_974, vb_974, vc_974, vd_974, target_6, target_8, target_9, target_10, func)
and not func_4(vctx_972, va_974, ve_974, target_11, target_6, func)
and not func_5(vd_974, ve_974, vstderr, target_12, target_13, target_14, func)
and func_6(vctx_972, va_974, vb_974, vc_974, ve_974, target_6)
and func_7(vb_974, target_7)
and func_8(vb_974, target_8)
and func_9(vc_974, target_9)
and func_10(vd_974, ve_974, target_10)
and func_11(va_974, target_11)
and func_12(vd_974, target_12)
and func_13(ve_974, target_13)
and func_14(vstderr, target_14)
and vctx_972.getType().hasName("BN_CTX *")
and va_974.getType().hasName("BIGNUM *")
and vb_974.getType().hasName("BIGNUM *")
and vc_974.getType().hasName("BIGNUM *")
and vd_974.getType().hasName("BIGNUM *")
and ve_974.getType().hasName("BIGNUM *")
and vstderr.getType().hasName("FILE *")
and vctx_972.getParentScope+() = func
and va_974.getParentScope+() = func
and vb_974.getParentScope+() = func
and vc_974.getParentScope+() = func
and vd_974.getParentScope+() = func
and ve_974.getParentScope+() = func
and not vstderr.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
