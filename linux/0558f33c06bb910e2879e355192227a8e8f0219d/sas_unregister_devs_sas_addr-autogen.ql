/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_unregister_devs_sas_addr
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-unregister-devs-sas-addr
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_unregister_devs_sas_addr function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sas_port_delete")
		and not target_0.getTarget().hasName("list_add_tail")
		and target_0.getArgument(0) instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Variable vphy_1895) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="port"
		and target_3.getQualifier().(VariableAccess).getTarget()=vphy_1895
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_4(Variable vphy_1895, Parameter vparent_1891) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("sas_disable_routing")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vparent_1891
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="attached_sas_addr"
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_1895)
}

from Function func, Variable vphy_1895, Parameter vparent_1891
where
func_0(func)
and func_3(vphy_1895)
and vphy_1895.getType().hasName("ex_phy *")
and vparent_1891.getType().hasName("domain_device *")
and func_4(vphy_1895, vparent_1891)
and vphy_1895.getParentScope+() = func
and vparent_1891.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
