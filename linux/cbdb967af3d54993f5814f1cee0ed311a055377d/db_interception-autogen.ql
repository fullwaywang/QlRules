/**
 * @name linux-cbdb967af3d54993f5814f1cee0ed311a055377d-db_interception
 * @id cpp/linux/cbdb967af3d54993f5814f1cee0ed311a055377d/db_interception
 * @description linux-cbdb967af3d54993f5814f1cee0ed311a055377d-db_interception CVE-2015-8104
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsvm_1660) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="vcpu"
		and target_0.getQualifier().(VariableAccess).getTarget()=vsvm_1660)
}

predicate func_1(Parameter vsvm_1660) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("update_db_bp_intercept")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand() instanceof PointerFieldAccess
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="nmi_singlestep"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvm_1660)
}

from Function func, Parameter vsvm_1660
where
func_0(vsvm_1660)
and func_1(vsvm_1660)
and vsvm_1660.getType().hasName("vcpu_svm *")
and vsvm_1660.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
