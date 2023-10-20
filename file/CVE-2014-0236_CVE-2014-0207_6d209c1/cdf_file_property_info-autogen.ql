/**
 * @name file-6d209c1c489457397a5763bca4b28e43aac90391-cdf_file_property_info
 * @id cpp/file/6d209c1c489457397a5763bca4b28e43aac90391/cdf-file-property-info
 * @description file-6d209c1c489457397a5763bca4b28e43aac90391-src/readcdf.c-cdf_file_property_info CVE-2014-0236
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vms_122, ExprStmt target_4, NotExpr target_2) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_122
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="1040"
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(VariableAccess).getType().hasName("const cdf_directory_t *")
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="d_storage_uuid"
		and target_1.getQualifier().(VariableAccess).getType().hasName("const cdf_directory_t *")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vms_122, ExprStmt target_4, NotExpr target_2) {
		target_2.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_122
		and target_2.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="1040"
		and target_2.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vclsid_123, VariableAccess target_3) {
		target_3.getTarget()=vclsid_123
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_clsid_to_mime")
}

predicate func_4(Parameter vclsid_123, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_clsid_to_mime")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclsid_123
}

from Function func, Parameter vms_122, Parameter vclsid_123, NotExpr target_2, VariableAccess target_3, ExprStmt target_4
where
not func_0(vms_122, target_4, target_2)
and not func_1(func)
and func_2(vms_122, target_4, target_2)
and func_3(vclsid_123, target_3)
and func_4(vclsid_123, target_4)
and vms_122.getType().hasName("magic_set *")
and vclsid_123.getType().hasName("const uint64_t[2]")
and vms_122.getParentScope+() = func
and vclsid_123.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
