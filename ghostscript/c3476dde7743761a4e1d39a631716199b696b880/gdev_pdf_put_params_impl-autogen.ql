/**
 * @name ghostscript-c3476dde7743761a4e1d39a631716199b696b880-gdev_pdf_put_params_impl
 * @id cpp/ghostscript/c3476dde7743761a4e1d39a631716199b696b880/gdev-pdf-put-params-impl
 * @description ghostscript-c3476dde7743761a4e1d39a631716199b696b880-devices/vector/gdevpdfp.c-gdev_pdf_put_params_impl CVE-2018-15910
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vparam_name_289, ExprStmt target_2, ExprStmt target_3) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vparam_name_289
		and target_0.getRValue() instanceof StringLiteral
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("param_read_bool")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("gs_param_list *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
		and target_2.getExpr().(ExprCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getLValue().(VariableAccess).getLocation())
		and target_0.getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(ExprCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vparam_name_289, ExprStmt target_2) {
		target_2.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="signal_error"
		and target_2.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_2.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gs_param_list *")
		and target_2.getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("gs_param_list *")
		and target_2.getExpr().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vparam_name_289
		and target_2.getExpr().(ExprCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Variable vparam_name_289, ExprStmt target_3) {
		target_3.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="signal_error"
		and target_3.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_3.getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("gs_param_list *")
		and target_3.getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("gs_param_list *")
		and target_3.getExpr().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vparam_name_289
		and target_3.getExpr().(ExprCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vparam_name_289, ExprStmt target_2, ExprStmt target_3
where
not func_0(vparam_name_289, target_2, target_3)
and func_2(vparam_name_289, target_2)
and func_3(vparam_name_289, target_3)
and vparam_name_289.getType().hasName("gs_param_name")
and vparam_name_289.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
