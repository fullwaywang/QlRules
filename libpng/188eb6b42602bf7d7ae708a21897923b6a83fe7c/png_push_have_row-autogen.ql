/**
 * @name libpng-188eb6b42602bf7d7ae708a21897923b6a83fe7c-png_push_have_row
 * @id cpp/libpng/188eb6b42602bf7d7ae708a21897923b6a83fe7c/png-push-have-row
 * @description libpng-188eb6b42602bf7d7ae708a21897923b6a83fe7c-png_push_have_row CVE-2010-1205
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_1683, Parameter vrow_1683) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="row_fn"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683
		and target_0.getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="row_fn"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1683
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vrow_1683
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="row_number"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pass"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683)
}

predicate func_1(Parameter vpng_ptr_1683) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="row_number"
		and target_1.getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683)
}

predicate func_2(Parameter vpng_ptr_1683, Parameter vrow_1683) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="row_number"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="row_fn"
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_1683
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vrow_1683
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="row_number"
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="pass"
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(ExprCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_1683)
}

from Function func, Parameter vpng_ptr_1683, Parameter vrow_1683
where
func_0(vpng_ptr_1683, vrow_1683)
and func_1(vpng_ptr_1683)
and func_2(vpng_ptr_1683, vrow_1683)
and vpng_ptr_1683.getType().hasName("png_structp")
and vrow_1683.getType().hasName("png_bytep")
and vpng_ptr_1683.getParentScope+() = func
and vrow_1683.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
