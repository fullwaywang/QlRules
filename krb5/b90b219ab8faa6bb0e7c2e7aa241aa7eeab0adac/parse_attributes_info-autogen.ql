/**
 * @name krb5-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-parse_attributes_info
 * @id cpp/krb5/b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac/parse-attributes-info
 * @description krb5-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-lib/krb5/pac.c-parse_attributes_info CVE-2022-42898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vattributes_info_1153, ExprStmt target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="offset"
		and target_0.getQualifier().(VariableAccess).getTarget()=vattributes_info_1153
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vattributes_info_1153, VariableAccess target_1) {
		target_1.getTarget()=vattributes_info_1153
}

predicate func_2(Parameter vattributes_info_1153, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="offset_lo"
		and target_2.getQualifier().(VariableAccess).getTarget()=vattributes_info_1153
}

predicate func_3(Parameter vattributes_info_1153, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("krb5_storage_from_readonly_mem")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset_lo"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattributes_info_1153
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattributes_info_1153
}

from Function func, Parameter vattributes_info_1153, VariableAccess target_1, PointerFieldAccess target_2, ExprStmt target_3
where
not func_0(vattributes_info_1153, target_3)
and func_1(vattributes_info_1153, target_1)
and func_2(vattributes_info_1153, target_2)
and func_3(vattributes_info_1153, target_3)
and vattributes_info_1153.getType().hasName("const PAC_INFO_BUFFER *")
and vattributes_info_1153.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
