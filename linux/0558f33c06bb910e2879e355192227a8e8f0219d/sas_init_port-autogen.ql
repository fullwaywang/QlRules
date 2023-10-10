/**
 * @name linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_init_port
 * @id cpp/linux/0558f33c06bb910e2879e355192227a8e8f0219d/sas-init-port
 * @description linux-0558f33c06bb910e2879e355192227a8e8f0219d-sas_init_port function
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vport_312) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="1128"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vport_312)
}

predicate func_1(Parameter vport_312, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("INIT_LIST_HEAD")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sas_port_del_list"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vport_312
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vport_312) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="destroy_list"
		and target_2.getQualifier().(VariableAccess).getTarget()=vport_312)
}

from Function func, Parameter vport_312
where
func_0(vport_312)
and not func_1(vport_312, func)
and vport_312.getType().hasName("asd_sas_port *")
and func_2(vport_312)
and vport_312.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
