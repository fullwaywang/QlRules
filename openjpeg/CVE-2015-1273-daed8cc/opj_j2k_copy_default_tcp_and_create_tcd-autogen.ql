/**
 * @name openjpeg-daed8cc9195555e101ab708a501af2dfe6d5e001-opj_j2k_copy_default_tcp_and_create_tcd
 * @id cpp/openjpeg/daed8cc9195555e101ab708a501af2dfe6d5e001/opj-j2k-copy-default-tcp-and-create-tcd
 * @description openjpeg-daed8cc9195555e101ab708a501af2dfe6d5e001-src/lib/openjp2/j2k.c-opj_j2k_copy_default_tcp_and_create_tcd CVE-2015-1273
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_tcp_7321, ExprStmt target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cod"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_7321
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vl_tcp_7321, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_tcp_7321
		and target_1.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="5680"
}

predicate func_2(Variable vl_tcp_7321, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ppt"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_7321
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vl_tcp_7321, ExprStmt target_1, ExprStmt target_2
where
not func_0(vl_tcp_7321, target_1, target_2)
and func_1(vl_tcp_7321, target_1)
and func_2(vl_tcp_7321, target_2)
and vl_tcp_7321.getType().hasName("opj_tcp_t *")
and vl_tcp_7321.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
