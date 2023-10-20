/**
 * @name zlib-1eb7682f845ac9e9bf9ae35bbfb3bad5dacbd91d-inflate
 * @id cpp/zlib/1eb7682f845ac9e9bf9ae35bbfb3bad5dacbd91d/inflate
 * @description zlib-1eb7682f845ac9e9bf9ae35bbfb3bad5dacbd91d-inflate.c-inflate CVE-2022-37434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstate_627, Variable vlen_638, AssignExpr target_0) {
		target_0.getLValue().(VariableAccess).getTarget()=vlen_638
		and target_0.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="extra_len"
		and target_0.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_0.getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_0.getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
}

predicate func_1(VariableAccess target_3, Function func, ExprStmt target_1) {
		target_1.getExpr() instanceof AssignExpr
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vlen_638, ExprStmt target_1, PointerArithmeticOperation target_4, VariableAccess target_2) {
		target_2.getTarget()=vlen_638
		and target_2.getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
}

predicate func_3(Variable vcopy_634, VariableAccess target_3) {
		target_3.getTarget()=vcopy_634
}

predicate func_4(Variable vstate_627, Variable vlen_638, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="extra"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_4.getAnOperand().(VariableAccess).getTarget()=vlen_638
}

from Function func, Variable vstate_627, Variable vcopy_634, Variable vlen_638, AssignExpr target_0, ExprStmt target_1, VariableAccess target_2, VariableAccess target_3, PointerArithmeticOperation target_4
where
func_0(vstate_627, vlen_638, target_0)
and func_1(target_3, func, target_1)
and func_2(vlen_638, target_1, target_4, target_2)
and func_3(vcopy_634, target_3)
and func_4(vstate_627, vlen_638, target_4)
and vstate_627.getType().hasName("inflate_state *")
and vcopy_634.getType().hasName("unsigned int")
and vlen_638.getType().hasName("unsigned int")
and vstate_627.getParentScope+() = func
and vcopy_634.getParentScope+() = func
and vlen_638.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
