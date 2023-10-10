/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-normal_scanLit
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/normal-scanLit
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmltok_impl.c-normal_scanLit CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vptr_941, Parameter vend_941, ArrayExpr target_4, RelationalOperation target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vptr_941
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vend_941
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vptr_941, Parameter vend_941, VariableAccess target_1) {
		target_1.getTarget()=vptr_941
		and target_1.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vend_941
}

*/
/*predicate func_2(Parameter vptr_941, Parameter vend_941, VariableAccess target_2) {
		target_2.getTarget()=vend_941
		and target_2.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vptr_941
}

*/
predicate func_3(Parameter vptr_941, Parameter vend_941, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vptr_941
		and target_3.getAnOperand().(VariableAccess).getTarget()=vend_941
}

predicate func_4(Parameter vptr_941, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="type"
		and target_4.getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_941
}

predicate func_5(Parameter vptr_941, Parameter vend_941, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vend_941
		and target_5.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vptr_941
		and target_5.getGreaterOperand().(Literal).getValue()="2"
}

from Function func, Parameter vptr_941, Parameter vend_941, EqualityOperation target_3, ArrayExpr target_4, RelationalOperation target_5
where
not func_0(vptr_941, vend_941, target_4, target_5)
and func_3(vptr_941, vend_941, target_3)
and func_4(vptr_941, target_4)
and func_5(vptr_941, vend_941, target_5)
and vptr_941.getType().hasName("const char *")
and vend_941.getType().hasName("const char *")
and vptr_941.getParentScope+() = func
and vend_941.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
