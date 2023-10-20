/**
 * @name php-c840f71524067aa474c00c3eacfb83bd860bfc8a-BF_decode
 * @id cpp/php/c840f71524067aa474c00c3eacfb83bd860bfc8a/BF-decode
 * @description php-c840f71524067aa474c00c3eacfb83bd860bfc8a-ext/standard/crypt_blowfish.c-BF_decode CVE-2023-0567
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtmp_386, IfStmt target_0) {
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtmp_386
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="36"
		and target_0.getThen().(BreakStmt).toString() = "break;"
}

predicate func_1(Variable vtmp_386, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtmp_386
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="36"
		and target_1.getThen().(BreakStmt).toString() = "break;"
}

predicate func_2(Variable vtmp_386, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtmp_386
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="36"
		and target_2.getThen().(BreakStmt).toString() = "break;"
}

predicate func_3(Variable vtmp_386, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtmp_386
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="36"
		and target_3.getThen().(BreakStmt).toString() = "break;"
}

predicate func_4(Parameter vsize_381, Variable vdptr_383, Variable vend_384, Function func, IfStmt target_4) {
		target_4.getCondition().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_384
		and target_4.getCondition().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdptr_383
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_381
		and target_4.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

/*predicate func_5(EqualityOperation target_7, Function func, ReturnStmt target_5) {
		target_5.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_5.getEnclosingFunction() = func
}

*/
predicate func_6(Variable vdptr_383, Variable vend_384, Function func, WhileStmt target_6) {
		target_6.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdptr_383
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vend_384
		and target_6.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdptr_383
		and target_6.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vsize_381, EqualityOperation target_7) {
		target_7.getAnOperand() instanceof PointerArithmeticOperation
		and target_7.getAnOperand().(VariableAccess).getTarget()=vsize_381
}

from Function func, Parameter vsize_381, Variable vdptr_383, Variable vend_384, Variable vtmp_386, IfStmt target_0, IfStmt target_1, IfStmt target_2, IfStmt target_3, IfStmt target_4, WhileStmt target_6, EqualityOperation target_7
where
func_0(vtmp_386, target_0)
and func_1(vtmp_386, target_1)
and func_2(vtmp_386, target_2)
and func_3(vtmp_386, target_3)
and func_4(vsize_381, vdptr_383, vend_384, func, target_4)
and func_6(vdptr_383, vend_384, func, target_6)
and func_7(vsize_381, target_7)
and vsize_381.getType().hasName("int")
and vdptr_383.getType().hasName("unsigned char *")
and vend_384.getType().hasName("unsigned char *")
and vtmp_386.getType().hasName("unsigned int")
and vsize_381.getParentScope+() = func
and vdptr_383.getParentScope+() = func
and vend_384.getParentScope+() = func
and vtmp_386.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
