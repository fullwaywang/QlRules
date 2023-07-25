/**
 * @name libpng-a8c319a2b281af68f7ca0e2f9a28ca57b44ceb2b-png_handle_sCAL
 * @id cpp/libpng/a8c319a2b281af68f7ca0e2f9a28ca57b44ceb2b/png-handle-sCAL
 * @description libpng-a8c319a2b281af68f7ca0e2f9a28ca57b44ceb2b-pngrutil.c-png_handle_sCAL CVE-2011-3045
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_1832, ExprStmt target_2, RelationalOperation target_3) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1832
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpng_ptr_1832, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="chunkdata"
		and target_1.getQualifier().(VariableAccess).getTarget()=vpng_ptr_1832
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

predicate func_2(Parameter vpng_ptr_1832, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1832
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vpng_ptr_1832, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chunkdata"
		and target_3.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1832
}

from Function func, Parameter vpng_ptr_1832, PointerFieldAccess target_1, ExprStmt target_2, RelationalOperation target_3
where
not func_0(vpng_ptr_1832, target_2, target_3)
and func_1(vpng_ptr_1832, target_1)
and func_2(vpng_ptr_1832, target_2)
and func_3(vpng_ptr_1832, target_3)
and vpng_ptr_1832.getType().hasName("png_structp")
and vpng_ptr_1832.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
