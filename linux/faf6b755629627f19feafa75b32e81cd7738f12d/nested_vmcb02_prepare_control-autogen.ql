/**
 * @name linux-faf6b755629627f19feafa75b32e81cd7738f12d-nested_vmcb02_prepare_control
 * @id cpp/linux/faf6b755629627f19feafa75b32e81cd7738f12d/nested_vmcb02_prepare_control
 * @description linux-faf6b755629627f19feafa75b32e81cd7738f12d-nested_vmcb02_prepare_control CVE-2021-3653
CVE-2021-3656
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsvm_507) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="control"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="vmcb"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvm_507)
}

predicate func_1(Parameter vsvm_507) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="ctl"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="nested"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvm_507)
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="virt_ext"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="virt_ext"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter vsvm_507
where
func_0(vsvm_507)
and func_1(vsvm_507)
and func_2(func)
and vsvm_507.getType().hasName("vcpu_svm *")
and vsvm_507.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
