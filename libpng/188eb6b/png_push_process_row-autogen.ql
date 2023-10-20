/**
 * @name libpng-188eb6b42602bf7d7ae708a21897923b6a83fe7c-png_push_process_row
 * @id cpp/libpng/188eb6b42602bf7d7ae708a21897923b6a83fe7c/png-push-process-row
 * @description libpng-188eb6b42602bf7d7ae708a21897923b6a83fe7c-png_push_process_row CVE-2010-1205
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpng_ptr_891, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="row_number"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_891
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="num_rows"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_891
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("png_error")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpng_ptr_891
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Extra row in image"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vpng_ptr_891) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(ValueFieldAccess).getTarget().getName()="color_type"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="row_info"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_891
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="color_type"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpng_ptr_891)
}

from Function func, Parameter vpng_ptr_891
where
not func_0(vpng_ptr_891, func)
and vpng_ptr_891.getType().hasName("png_structp")
and func_3(vpng_ptr_891)
and vpng_ptr_891.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
