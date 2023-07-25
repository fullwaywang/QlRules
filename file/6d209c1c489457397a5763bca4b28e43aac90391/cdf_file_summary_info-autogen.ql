/**
 * @name file-6d209c1c489457397a5763bca4b28e43aac90391-cdf_file_summary_info
 * @id cpp/file/6d209c1c489457397a5763bca4b28e43aac90391/cdf-file-summary-info
 * @description file-6d209c1c489457397a5763bca4b28e43aac90391-src/readcdf.c-cdf_file_summary_info CVE-2014-0236
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstr_250, Variable vclsid2desc, EqualityOperation target_6, IfStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getType().hasName("const cdf_directory_t *")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstr_250
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_clsid_to_mime")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="d_storage_uuid"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const cdf_directory_t *")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vclsid2desc
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation()))
}

/*predicate func_1(Function func) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="d_storage_uuid"
		and target_1.getQualifier().(VariableAccess).getType().hasName("const cdf_directory_t *")
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_3(Variable vstr_250, Parameter vms_238, EqualityOperation target_6, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vstr_250
		and target_3.getThen().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("file_printf")
		and target_3.getThen().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vms_238
		and target_3.getThen().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=", %s"
		and target_3.getThen().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_250
		and target_3.getThen().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_3.getThen().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-2"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_4(Variable vclsid2desc, Parameter vclsid_239, ExprStmt target_7, VariableAccess target_4) {
		target_4.getTarget()=vclsid_239
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_clsid_to_mime")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vclsid2desc
		and target_4.getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
}

predicate func_5(Parameter vclsid_239, Parameter vms_238, ExprStmt target_8, EqualityOperation target_9, VariableAccess target_5) {
		target_5.getTarget()=vclsid_239
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_file_property_info")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vms_238
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getLocation())
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_6(Parameter vms_238, EqualityOperation target_6) {
		target_6.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_6.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_238
		and target_6.getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="1040"
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Parameter vclsid_239, Parameter vms_238, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_file_property_info")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vms_238
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vclsid_239
}

predicate func_8(Variable vstr_250, Variable vclsid2desc, Parameter vclsid_239, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstr_250
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_clsid_to_mime")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclsid_239
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vclsid2desc
}

predicate func_9(Variable vstr_250, Parameter vms_238, EqualityOperation target_9) {
		target_9.getAnOperand().(FunctionCall).getTarget().hasName("file_printf")
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vms_238
		and target_9.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=", %s"
		and target_9.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_250
		and target_9.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Variable vstr_250, Variable vclsid2desc, Parameter vclsid_239, Parameter vms_238, IfStmt target_3, VariableAccess target_4, VariableAccess target_5, EqualityOperation target_6, ExprStmt target_7, ExprStmt target_8, EqualityOperation target_9
where
not func_0(vstr_250, vclsid2desc, target_6, target_3)
and func_3(vstr_250, vms_238, target_6, target_3)
and func_4(vclsid2desc, vclsid_239, target_7, target_4)
and func_5(vclsid_239, vms_238, target_8, target_9, target_5)
and func_6(vms_238, target_6)
and func_7(vclsid_239, vms_238, target_7)
and func_8(vstr_250, vclsid2desc, vclsid_239, target_8)
and func_9(vstr_250, vms_238, target_9)
and vstr_250.getType().hasName("const char *")
and vclsid2desc.getType() instanceof ArrayType
and vclsid_239.getType().hasName("const uint64_t[2]")
and vms_238.getType().hasName("magic_set *")
and vstr_250.getParentScope+() = func
and not vclsid2desc.getParentScope+() = func
and vclsid_239.getParentScope+() = func
and vms_238.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
