/**
 * @name linux-34e5b01186858b36c4d7c87e1a025071e8e2401f-sctp_do_bind
 * @id cpp/linux/34e5b01186858b36c4d7c87e1a025071e8e2401f/sctp_do_bind
 * @description linux-34e5b01186858b36c4d7c87e1a025071e8e2401f-sctp_do_bind CVE-2021-23133
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_364, Variable vbp_366) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sctp_auto_asconf_init")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsp_364
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="port"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbp_366)
}

predicate func_1(Parameter vsk_361, Variable vbp_366) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="port"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbp_366
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="skc_num"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="__sk_common"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sk"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("inet_sk")
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_361
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="port"
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbp_366)
}

predicate func_2(Parameter vaddr_361, Variable vsp_364, Variable vbp_366) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sctp_bind_addr_match")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vbp_366
		and target_2.getArgument(1).(VariableAccess).getTarget()=vaddr_361
		and target_2.getArgument(2).(VariableAccess).getTarget()=vsp_364)
}

from Function func, Parameter vsk_361, Parameter vaddr_361, Variable vsp_364, Variable vbp_366
where
not func_0(vsp_364, vbp_366)
and func_1(vsk_361, vbp_366)
and vsk_361.getType().hasName("sock *")
and vsp_364.getType().hasName("sctp_sock *")
and func_2(vaddr_361, vsp_364, vbp_366)
and vbp_366.getType().hasName("sctp_bind_addr *")
and vsk_361.getParentScope+() = func
and vaddr_361.getParentScope+() = func
and vsp_364.getParentScope+() = func
and vbp_366.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
