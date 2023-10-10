/**
 * @name linux-f60a85cad677c4f9bb4cadd764f1d106c38c7cf8-umd_cleanup
 * @id cpp/linux/f60a85cad677c4f9bb4cadd764f1d106c38c7cf8/umd_cleanup
 * @description linux-f60a85cad677c4f9bb4cadd764f1d106c38c7cf8-umd_cleanup 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vumd_info_139) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("fput")
		and not target_0.getTarget().hasName("umd_cleanup_helper")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="pipe_to_umh"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vumd_info_139)
}

predicate func_2(Parameter vinfo_137, Variable vumd_info_139) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("fput")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pipe_from_umh"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vumd_info_139
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="retval"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_137)
}

predicate func_3(Parameter vinfo_137, Variable vumd_info_139) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("put_pid")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tgid"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vumd_info_139
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="retval"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_137)
}

predicate func_4(Parameter vinfo_137, Variable vumd_info_139) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tgid"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vumd_info_139
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="retval"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_137)
}

from Function func, Parameter vinfo_137, Variable vumd_info_139
where
func_0(vumd_info_139)
and func_2(vinfo_137, vumd_info_139)
and func_3(vinfo_137, vumd_info_139)
and func_4(vinfo_137, vumd_info_139)
and vinfo_137.getType().hasName("subprocess_info *")
and vumd_info_139.getType().hasName("umd_info *")
and vinfo_137.getParentScope+() = func
and vumd_info_139.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
