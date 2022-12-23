/**
 * @name linux-cbdb967af3d54993f5814f1cee0ed311a055377d-enable_nmi_window
 * @id cpp/linux/cbdb967af3d54993f5814f1cee0ed311a055377d/enable_nmi_window
 * @description linux-cbdb967af3d54993f5814f1cee0ed311a055377d-enable_nmi_window CVE-2015-8104
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vvcpu_3650, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("update_db_bp_intercept")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_3650
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vvcpu_3650
where
func_0(vvcpu_3650, func)
and vvcpu_3650.getType().hasName("kvm_vcpu *")
and vvcpu_3650.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
